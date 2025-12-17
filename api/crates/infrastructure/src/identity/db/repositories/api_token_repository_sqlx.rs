use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use application::identity::ports::api_token_repository::{
    ApiToken, ApiTokenRepository, ApiTokenSecret,
};
use crate::core::db::PgPool;

pub struct SqlxApiTokenRepository {
    pool: PgPool,
}

impl SqlxApiTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApiTokenRepository for SqlxApiTokenRepository {
    async fn create(
        &self,
        workspace_id: Uuid,
        owner_id: Uuid,
        name: &str,
        token_hash: &str,
        token_digest: &str,
    ) -> anyhow::Result<ApiToken> {
        let row = sqlx::query(
            r#"INSERT INTO api_tokens (workspace_id, owner_id, name, token_hash, token_digest)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING id, workspace_id, owner_id, name, created_at, last_used_at, revoked_at"#,
        )
        .bind(workspace_id)
        .bind(owner_id)
        .bind(name)
        .bind(token_hash)
        .bind(token_digest)
        .fetch_one(&self.pool)
        .await?;

        Ok(ApiToken {
            id: row.get("id"),
            workspace_id: row.get("workspace_id"),
            owner_id: row.get("owner_id"),
            name: row.get("name"),
            created_at: row.get("created_at"),
            last_used_at: row.try_get("last_used_at").ok(),
            revoked_at: row.try_get("revoked_at").ok(),
        })
    }

    async fn list_active(&self, workspace_id: Uuid) -> anyhow::Result<Vec<ApiToken>> {
        let rows = sqlx::query(
            r#"SELECT id, workspace_id, owner_id, name, created_at, last_used_at, revoked_at
               FROM api_tokens
               WHERE workspace_id = $1
               ORDER BY created_at DESC"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| ApiToken {
                id: row.get("id"),
                workspace_id: row.get("workspace_id"),
                owner_id: row.get("owner_id"),
                name: row.get("name"),
                created_at: row.get("created_at"),
                last_used_at: row.try_get("last_used_at").ok(),
                revoked_at: row.try_get("revoked_at").ok(),
            })
            .collect())
    }

    async fn revoke(&self, workspace_id: Uuid, token_id: Uuid) -> anyhow::Result<bool> {
        let row = sqlx::query(
            r#"UPDATE api_tokens
               SET revoked_at = now()
               WHERE id = $1 AND workspace_id = $2 AND revoked_at IS NULL
               RETURNING id"#,
        )
        .bind(token_id)
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    async fn find_by_digest(&self, digest: &str) -> anyhow::Result<Option<ApiTokenSecret>> {
        let row = sqlx::query(
            r#"SELECT id, workspace_id, owner_id, name, created_at, last_used_at, revoked_at, token_hash, token_digest
               FROM api_tokens
               WHERE token_digest = $1
               LIMIT 1"#,
        )
        .bind(digest)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| {
            let token = ApiToken {
                id: row.get("id"),
                workspace_id: row.get("workspace_id"),
                owner_id: row.get("owner_id"),
                name: row.get("name"),
                created_at: row.get("created_at"),
                last_used_at: row.try_get("last_used_at").ok(),
                revoked_at: row.try_get("revoked_at").ok(),
            };
            ApiTokenSecret {
                token,
                token_hash: row.get("token_hash"),
                token_digest: row.get("token_digest"),
            }
        }))
    }

    async fn touch_last_used(&self, token_id: Uuid) -> anyhow::Result<()> {
        sqlx::query("UPDATE api_tokens SET last_used_at = now() WHERE id = $1")
            .bind(token_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
