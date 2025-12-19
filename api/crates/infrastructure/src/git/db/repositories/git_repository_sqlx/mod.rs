use async_trait::async_trait;
use sqlx::{Row, error::DatabaseError};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;

use crate::core::crypto;
use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::git::ports::git_repository::{
    GitConfigRecord, GitLastSyncLog, GitRepository, UserGitCfg,
};
use domain::git::auth::GitAuthType;
use domain::git::sync_log::{GitSyncOperation, GitSyncStatus};

pub struct SqlxGitRepository {
    pub pool: PgPool,
    encryption_key: String,
    workspace_constraint_checked: AtomicBool,
    workspace_constraint_check_lock: Mutex<()>,
}

impl SqlxGitRepository {
    pub fn new(pool: PgPool, encryption_key: impl Into<String>) -> Self {
        Self {
            pool,
            encryption_key: encryption_key.into(),
            workspace_constraint_checked: AtomicBool::new(false),
            workspace_constraint_check_lock: Mutex::new(()),
        }
    }

    async fn ensure_workspace_unique_constraint_ready(&self) -> anyhow::Result<()> {
        if self.workspace_constraint_checked.load(Ordering::Relaxed) {
            return Ok(());
        }

        let _guard = self.workspace_constraint_check_lock.lock().await;
        if self.workspace_constraint_checked.load(Ordering::Relaxed) {
            return Ok(());
        }

        let constraint_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'git_configs_workspace_unique')",
        )
        .fetch_one(&self.pool)
        .await?;

        if !constraint_exists {
            self.repair_workspace_unique_constraint().await?;
        }

        self.workspace_constraint_checked
            .store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn repair_workspace_unique_constraint(&self) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("LOCK TABLE git_configs IN EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;

        let constraint_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'git_configs_workspace_unique')",
        )
        .fetch_one(&mut *tx)
        .await?;

        if constraint_exists {
            tx.commit().await?;
            return Ok(());
        }

        let dedup = sqlx::query(
            r#"WITH ranked AS (
                SELECT
                    id,
                    ROW_NUMBER() OVER (
                        PARTITION BY workspace_id
                        ORDER BY updated_at DESC, created_at DESC, id DESC
                    ) AS rn
                FROM git_configs
            )
            DELETE FROM git_configs gc
            USING ranked r
            WHERE gc.id = r.id
              AND r.rn > 1;"#,
        )
        .execute(&mut *tx)
        .await?;
        if dedup.rows_affected() > 0 {
            warn!(
                rows = dedup.rows_affected(),
                "git_configs_workspace_unique_repair_deduped"
            );
        }

        if let Err(err) = sqlx::query(
            "ALTER TABLE git_configs ADD CONSTRAINT git_configs_workspace_unique UNIQUE (workspace_id)",
        )
        .execute(&mut *tx)
        .await
        {
            match err {
                sqlx::Error::Database(db_err) => {
                    let is_duplicate = db_err.code().map(|c| c == "42710").unwrap_or(false);
                    if !is_duplicate {
                        return Err(sqlx::Error::Database(db_err).into());
                    }
                }
                other => return Err(other.into()),
            }
        }

        tx.commit().await?;
        Ok(())
    }
}

#[async_trait]
impl GitRepository for SqlxGitRepository {
    async fn get_config(&self, workspace_id: Uuid) -> PortResult<Option<GitConfigRecord>> {
        let out: anyhow::Result<Option<GitConfigRecord>> = async {
            let row = sqlx::query("SELECT id, repository_url, branch_name, auth_type, auto_sync, created_at, updated_at FROM git_configs WHERE workspace_id = $1 LIMIT 1")
                .bind(workspace_id)
                .fetch_optional(&self.pool)
                .await?;
            row.map(|r| {
                let auth_type_raw: String = r.get("auth_type");
                let auth_type = GitAuthType::parse(&auth_type_raw)
                    .ok_or_else(|| anyhow::anyhow!("invalid_git_auth_type"))?;
                Ok(GitConfigRecord {
                    id: r.get("id"),
                    repository_url: r.get("repository_url"),
                    branch_name: r.get("branch_name"),
                    auth_type,
                    auto_sync: r.get("auto_sync"),
                    created_at: r.get("created_at"),
                    updated_at: r.get("updated_at"),
                })
            })
            .transpose()
        }
        .await;
        out.map_err(Into::into)
    }

    async fn upsert_config(
        &self,
        workspace_id: Uuid,
        repository_url: &str,
        branch_name: Option<&str>,
        auth_type: GitAuthType,
        auth_data: &serde_json::Value,
        auto_sync: Option<bool>,
    ) -> PortResult<GitConfigRecord> {
        let out: anyhow::Result<GitConfigRecord> = async {
            self.ensure_workspace_unique_constraint_ready().await?;
            let enc_auth = crypto::encrypt_auth_data(&self.encryption_key, auth_data);
            let mut repaired_constraint = false;
            loop {
                let query = sqlx::query(
                    r#"INSERT INTO git_configs (workspace_id, repository_url, branch_name, auth_type, auth_data, auto_sync)
                   VALUES ($1, $2, COALESCE($3, 'main'), $4, $5, COALESCE($6, true))
                   ON CONFLICT ON CONSTRAINT git_configs_workspace_unique DO UPDATE SET
                     repository_url = EXCLUDED.repository_url,
                     branch_name = EXCLUDED.branch_name,
                     auth_type = EXCLUDED.auth_type,
                     auth_data = EXCLUDED.auth_data,
                     auto_sync = EXCLUDED.auto_sync,
                     updated_at = now()
                   RETURNING id, repository_url, branch_name, auth_type, auto_sync, created_at, updated_at"#
                )
                .bind(workspace_id)
                .bind(repository_url)
                .bind(branch_name)
                .bind(auth_type.as_str())
                .bind(&enc_auth)
                .bind(auto_sync);

                match query.fetch_one(&self.pool).await {
                    Ok(row) => {
                        let auth_type_raw: String = row.get("auth_type");
                        let parsed_auth_type = GitAuthType::parse(&auth_type_raw)
                            .ok_or_else(|| anyhow::anyhow!("invalid_git_auth_type"))?;
                        break Ok(GitConfigRecord {
                            id: row.get("id"),
                            repository_url: row.get("repository_url"),
                            branch_name: row.get("branch_name"),
                            auth_type: parsed_auth_type,
                            auto_sync: row.get("auto_sync"),
                            created_at: row.get("created_at"),
                            updated_at: row.get("updated_at"),
                        });
                    }
                    Err(sqlx::Error::Database(db_err)) => {
                        if !repaired_constraint
                            && is_missing_workspace_unique_error(db_err.as_ref())
                        {
                            warn!(
                                workspace_id = %workspace_id,
                                "git_configs_workspace_unique_missing_repair"
                            );
                            self.repair_workspace_unique_constraint().await?;
                            repaired_constraint = true;
                            continue;
                        }
                        break Err(sqlx::Error::Database(db_err).into());
                    }
                    Err(err) => break Err(err.into()),
                }
            }
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_config(&self, workspace_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let res = sqlx::query("DELETE FROM git_configs WHERE workspace_id = $1")
                .bind(workspace_id)
                .execute(&self.pool)
                .await?;
            Ok(res.rows_affected() > 0)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn load_user_git_cfg(&self, workspace_id: Uuid) -> PortResult<Option<UserGitCfg>> {
        let out: anyhow::Result<Option<UserGitCfg>> = async {
            let row = sqlx::query("SELECT repository_url, branch_name, auth_type, auth_data, auto_sync FROM git_configs WHERE workspace_id = $1 LIMIT 1")
                .bind(workspace_id)
                .fetch_optional(&self.pool)
                .await?;
            row.map(|r| {
                let repository_url: String = r.get("repository_url");
                let branch_name: String = r.get("branch_name");
                let auth_type_raw: Option<String> = r.try_get("auth_type").ok();
                let auth_type = match auth_type_raw.as_deref() {
                    None => None,
                    Some(value) => Some(
                        GitAuthType::parse(value)
                            .ok_or_else(|| anyhow::anyhow!("invalid_git_auth_type"))?,
                    ),
                };
                let raw_auth: Option<serde_json::Value> = r.try_get("auth_data").ok();
                let auth_data =
                    raw_auth.map(|v| crypto::decrypt_auth_data(&self.encryption_key, &v));
                let auto_sync: bool = r.try_get("auto_sync").unwrap_or(true);
                Ok(UserGitCfg {
                    repository_url,
                    branch_name,
                    auth_type,
                    auth_data,
                    auto_sync,
                })
            })
            .transpose()
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_last_sync_log(&self, workspace_id: Uuid) -> PortResult<Option<GitLastSyncLog>> {
        let out: anyhow::Result<Option<GitLastSyncLog>> = async {
            let row = sqlx::query("SELECT status, message, commit_hash, created_at FROM git_sync_logs WHERE workspace_id = $1 ORDER BY created_at DESC LIMIT 1")
                .bind(workspace_id)
                .fetch_optional(&self.pool)
                .await?;
            row.map(|r| {
                let status_raw: Option<String> = r.try_get("status").ok();
                let status = match status_raw.as_deref() {
                    None => None,
                    Some(value) => Some(
                        GitSyncStatus::parse(value)
                            .ok_or_else(|| anyhow::anyhow!("invalid_git_sync_status"))?,
                    ),
                };
                Ok(GitLastSyncLog {
                    created_at: r.try_get("created_at").ok(),
                    status,
                    message: r.try_get("message").ok(),
                    commit_hash: r.try_get("commit_hash").ok(),
                })
            })
            .transpose()
        }
        .await;
        out.map_err(Into::into)
    }

    async fn log_sync_operation(
        &self,
        workspace_id: Uuid,
        operation: GitSyncOperation,
        status: GitSyncStatus,
        message: Option<&str>,
        commit_hash: Option<&str>,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            let _ = sqlx::query("INSERT INTO git_sync_logs (workspace_id, operation, status, message, commit_hash) VALUES ($1, $2, $3, $4, $5)")
                .bind(workspace_id)
                .bind(operation.as_str())
                .bind(status.as_str())
                .bind(message)
                .bind(commit_hash)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_sync_logs(&self, workspace_id: Uuid) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query("DELETE FROM git_sync_logs WHERE workspace_id = $1")
                .bind(workspace_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_repository_state(&self, workspace_id: Uuid) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query("DELETE FROM git_repository_state WHERE workspace_id = $1")
                .bind(workspace_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn list_auto_sync_workspaces(&self) -> PortResult<Vec<Uuid>> {
        let out: anyhow::Result<Vec<Uuid>> = async {
            let rows = sqlx::query(
                "SELECT workspace_id FROM git_configs WHERE auto_sync IS DISTINCT FROM false",
            )
            .fetch_all(&self.pool)
            .await?;
            Ok(rows
                .into_iter()
                .filter_map(|r| r.try_get("workspace_id").ok())
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }
}

fn is_missing_workspace_unique_error(err: &dyn DatabaseError) -> bool {
    let code_matches = err
        .code()
        .map(|c| c == "42P10" || c == "42704")
        .unwrap_or(false);
    code_matches
        || err.message().contains(
            "there is no unique or exclusion constraint matching the ON CONFLICT specification",
        )
        || err.message().contains(
            "constraint \"git_configs_workspace_unique\" for table \"git_configs\" does not exist",
        )
}
