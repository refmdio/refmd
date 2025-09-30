use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::git_repository::{GitRepository, UserGitCfg};
use crate::infrastructure::crypto;
use crate::infrastructure::db::PgPool;

pub struct SqlxGitRepository {
    pub pool: PgPool,
    encryption_key: String,
}

impl SqlxGitRepository {
    pub fn new(pool: PgPool, encryption_key: impl Into<String>) -> Self {
        Self {
            pool,
            encryption_key: encryption_key.into(),
        }
    }
}

#[async_trait]
impl GitRepository for SqlxGitRepository {
    async fn get_config(
        &self,
        user_id: Uuid,
    ) -> anyhow::Result<
        Option<(
            Uuid,
            String,
            String,
            String,
            bool,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )>,
    > {
        let row = sqlx::query("SELECT id, repository_url, branch_name, auth_type, auto_sync, created_at, updated_at FROM git_configs WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| {
            (
                r.get("id"),
                r.get("repository_url"),
                r.get("branch_name"),
                r.get("auth_type"),
                r.get("auto_sync"),
                r.get("created_at"),
                r.get("updated_at"),
            )
        }))
    }

    async fn upsert_config(
        &self,
        user_id: Uuid,
        repository_url: &str,
        branch_name: Option<&str>,
        auth_type: &str,
        auth_data: &serde_json::Value,
        auto_sync: Option<bool>,
    ) -> anyhow::Result<(
        Uuid,
        String,
        String,
        String,
        bool,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> {
        let enc_auth = crypto::encrypt_auth_data(&self.encryption_key, auth_data);
        let row = sqlx::query(
            r#"INSERT INTO git_configs (user_id, repository_url, branch_name, auth_type, auth_data, auto_sync)
               VALUES ($1, $2, COALESCE($3, 'main'), $4, $5, COALESCE($6, true))
               ON CONFLICT ON CONSTRAINT git_configs_user_id_unique DO UPDATE SET
                 repository_url = EXCLUDED.repository_url,
                 branch_name = EXCLUDED.branch_name,
                 auth_type = EXCLUDED.auth_type,
                 auth_data = EXCLUDED.auth_data,
                 auto_sync = EXCLUDED.auto_sync,
                 updated_at = now()
               RETURNING id, repository_url, branch_name, auth_type, auto_sync, created_at, updated_at"#
        )
        .bind(user_id)
        .bind(repository_url)
        .bind(branch_name)
        .bind(auth_type)
        .bind(&enc_auth)
        .bind(auto_sync)
        .fetch_one(&self.pool)
        .await?;
        Ok((
            row.get("id"),
            row.get("repository_url"),
            row.get("branch_name"),
            row.get("auth_type"),
            row.get("auto_sync"),
            row.get("created_at"),
            row.get("updated_at"),
        ))
    }

    async fn delete_config(&self, user_id: Uuid) -> anyhow::Result<bool> {
        let res = sqlx::query("DELETE FROM git_configs WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn load_user_git_cfg(&self, user_id: Uuid) -> anyhow::Result<Option<UserGitCfg>> {
        let row = sqlx::query("SELECT repository_url, branch_name, auth_type, auth_data, auto_sync FROM git_configs WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| {
            let repository_url: String = r.get("repository_url");
            let branch_name: String = r.get("branch_name");
            let auth_type: Option<String> = r.try_get("auth_type").ok();
            let raw_auth: Option<serde_json::Value> = r.try_get("auth_data").ok();
            let auth_data = raw_auth.map(|v| crypto::decrypt_auth_data(&self.encryption_key, &v));
            let auto_sync: bool = r.try_get("auto_sync").unwrap_or(true);
            UserGitCfg {
                repository_url,
                branch_name,
                auth_type,
                auth_data,
                auto_sync,
            }
        }))
    }

    async fn get_last_sync_log(
        &self,
        user_id: Uuid,
    ) -> anyhow::Result<
        Option<(
            Option<chrono::DateTime<chrono::Utc>>,
            Option<String>,
            Option<String>,
            Option<String>,
        )>,
    > {
        let row = sqlx::query("SELECT status, message, commit_hash, created_at FROM git_sync_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| {
            (
                r.try_get("created_at").ok(),
                r.try_get("status").ok(),
                r.try_get("message").ok(),
                r.try_get("commit_hash").ok(),
            )
        }))
    }

    async fn log_sync_operation(
        &self,
        user_id: Uuid,
        operation: &str,
        status: &str,
        message: Option<&str>,
        commit_hash: Option<&str>,
    ) -> anyhow::Result<()> {
        let _ = sqlx::query("INSERT INTO git_sync_logs (user_id, operation, status, message, commit_hash) VALUES ($1, $2, $3, $4, $5)")
            .bind(user_id)
            .bind(operation)
            .bind(status)
            .bind(message)
            .bind(commit_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_sync_logs(&self, user_id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM git_sync_logs WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_repository_state(&self, user_id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM git_repository_state WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
