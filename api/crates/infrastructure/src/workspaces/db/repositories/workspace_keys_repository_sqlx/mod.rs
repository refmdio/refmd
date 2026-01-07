use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::workspaces::ports::workspace_keys_repository::{
    WorkspaceEncryptedKeyRow, WorkspaceKeysRepository,
};

pub struct SqlxWorkspaceKeysRepository {
    pool: PgPool,
}

impl SqlxWorkspaceKeysRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WorkspaceKeysRepository for SqlxWorkspaceKeysRepository {
    async fn get_encrypted_kek(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> PortResult<Option<WorkspaceEncryptedKeyRow>> {
        let out: anyhow::Result<Option<WorkspaceEncryptedKeyRow>> = async {
            let row = sqlx::query(
                r#"SELECT id, workspace_id, user_id, encrypted_kek, key_version, created_at
                   FROM workspace_encrypted_keys
                   WHERE workspace_id = $1 AND user_id = $2
                   ORDER BY key_version DESC
                   LIMIT 1"#,
            )
            .bind(workspace_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.map(|row| WorkspaceEncryptedKeyRow {
                id: row.get("id"),
                workspace_id: row.get("workspace_id"),
                user_id: row.get("user_id"),
                encrypted_kek: row.get("encrypted_kek"),
                key_version: row.get("key_version"),
                created_at: row.get("created_at"),
            }))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn list_encrypted_keks(
        &self,
        workspace_id: Uuid,
    ) -> PortResult<Vec<WorkspaceEncryptedKeyRow>> {
        let out: anyhow::Result<Vec<WorkspaceEncryptedKeyRow>> = async {
            let rows = sqlx::query(
                r#"SELECT DISTINCT ON (user_id) id, workspace_id, user_id, encrypted_kek, key_version, created_at
                   FROM workspace_encrypted_keys
                   WHERE workspace_id = $1
                   ORDER BY user_id, key_version DESC"#,
            )
            .bind(workspace_id)
            .fetch_all(&self.pool)
            .await?;

            Ok(rows
                .into_iter()
                .map(|row| WorkspaceEncryptedKeyRow {
                    id: row.get("id"),
                    workspace_id: row.get("workspace_id"),
                    user_id: row.get("user_id"),
                    encrypted_kek: row.get("encrypted_kek"),
                    key_version: row.get("key_version"),
                    created_at: row.get("created_at"),
                })
                .collect())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn upsert_encrypted_kek(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        encrypted_kek: &[u8],
        key_version: i32,
    ) -> PortResult<WorkspaceEncryptedKeyRow> {
        let out: anyhow::Result<WorkspaceEncryptedKeyRow> = async {
            let row = sqlx::query(
                r#"INSERT INTO workspace_encrypted_keys (workspace_id, user_id, encrypted_kek, key_version, created_at)
                   VALUES ($1, $2, $3, $4, now())
                   ON CONFLICT (workspace_id, user_id, key_version)
                   DO UPDATE SET
                     encrypted_kek = EXCLUDED.encrypted_kek
                   RETURNING id, workspace_id, user_id, encrypted_kek, key_version, created_at"#,
            )
            .bind(workspace_id)
            .bind(user_id)
            .bind(encrypted_kek)
            .bind(key_version)
            .fetch_one(&self.pool)
            .await?;

            Ok(WorkspaceEncryptedKeyRow {
                id: row.get("id"),
                workspace_id: row.get("workspace_id"),
                user_id: row.get("user_id"),
                encrypted_kek: row.get("encrypted_kek"),
                key_version: row.get("key_version"),
                created_at: row.get("created_at"),
            })
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_encrypted_kek(&self, workspace_id: Uuid, user_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let result = sqlx::query(
                r#"DELETE FROM workspace_encrypted_keys
                   WHERE workspace_id = $1 AND user_id = $2"#,
            )
            .bind(workspace_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

            Ok(result.rows_affected() > 0)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_encrypted_kek_version(
        &self,
        workspace_id: Uuid,
        key_version: i32,
    ) -> PortResult<u64> {
        let out: anyhow::Result<u64> = async {
            let result = sqlx::query(
                r#"DELETE FROM workspace_encrypted_keys
                   WHERE workspace_id = $1 AND key_version = $2"#,
            )
            .bind(workspace_id)
            .bind(key_version)
            .execute(&self.pool)
            .await?;

            Ok(result.rows_affected())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_current_key_version(&self, workspace_id: Uuid) -> PortResult<Option<i32>> {
        let out: anyhow::Result<Option<i32>> = async {
            let row = sqlx::query(
                r#"SELECT MAX(key_version) as max_version
                   FROM workspace_encrypted_keys
                   WHERE workspace_id = $1"#,
            )
            .bind(workspace_id)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.and_then(|r| r.try_get::<Option<i32>, _>("max_version").ok().flatten()))
        }
        .await;
        out.map_err(Into::into)
    }
}
