use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use application::identity::ports::user_session_repository::{
    UserSessionRecord, UserSessionRepository, UserSessionSecret,
};
use crate::core::db::PgPool;

pub struct SqlxUserSessionRepository {
    pool: PgPool,
}

impl SqlxUserSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn map_record(row: sqlx::postgres::PgRow) -> UserSessionRecord {
        UserSessionRecord {
            id: row.get("id"),
            user_id: row.get("user_id"),
            workspace_id: row.get("workspace_id"),
            user_agent: row.try_get("user_agent").ok(),
            ip_address: row.try_get("ip_address").ok(),
            remember_me: row.get("remember_me"),
            created_at: row.get("created_at"),
            last_seen_at: row.get("last_seen_at"),
            expires_at: row.get("expires_at"),
            revoked_at: row.try_get("revoked_at").ok(),
        }
    }
}

#[async_trait]
impl UserSessionRepository for SqlxUserSessionRepository {
    async fn create(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
        token_hash: &str,
        token_digest: &str,
        expires_at: DateTime<Utc>,
        remember_me: bool,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> anyhow::Result<UserSessionRecord> {
        let row = sqlx::query(
            r#"INSERT INTO user_sessions
               (user_id, workspace_id, token_hash, token_digest, expires_at, remember_me, user_agent, ip_address)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING id, user_id, workspace_id, user_agent, ip_address, remember_me, created_at, last_seen_at, expires_at, revoked_at"#,
        )
        .bind(user_id)
        .bind(workspace_id)
        .bind(token_hash)
        .bind(token_digest)
        .bind(expires_at)
        .bind(remember_me)
        .bind(user_agent)
        .bind(ip_address)
        .fetch_one(&self.pool)
        .await?;

        Ok(Self::map_record(row))
    }

    async fn find_by_digest(
        &self,
        token_digest: &str,
    ) -> anyhow::Result<Option<UserSessionSecret>> {
        let row = sqlx::query(
            r#"SELECT id, user_id, workspace_id, user_agent, ip_address, remember_me,
                       created_at, last_seen_at, expires_at, revoked_at, token_hash, token_digest
               FROM user_sessions
               WHERE token_digest = $1
               LIMIT 1"#,
        )
        .bind(token_digest)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| UserSessionSecret {
            token_hash: row.get("token_hash"),
            token_digest: row.get("token_digest"),
            session: Self::map_record(row),
        }))
    }

    async fn update_token(
        &self,
        session_id: Uuid,
        expected_token_digest: &str,
        token_hash: &str,
        token_digest: &str,
        expires_at: DateTime<Utc>,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
        workspace_id: Option<Uuid>,
    ) -> anyhow::Result<bool> {
        let row = sqlx::query(
            r#"UPDATE user_sessions
               SET token_hash = $2,
                   token_digest = $3,
                   expires_at = $4,
                   last_seen_at = now(),
                   user_agent = $5,
                   ip_address = $6,
                   workspace_id = COALESCE($8, workspace_id)
               WHERE id = $1
                 AND revoked_at IS NULL
                 AND token_digest = $7
               RETURNING id"#,
        )
        .bind(session_id)
        .bind(token_hash)
        .bind(token_digest)
        .bind(expires_at)
        .bind(user_agent)
        .bind(ip_address)
        .bind(expected_token_digest)
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    async fn update_workspace(&self, session_id: Uuid, workspace_id: Uuid) -> anyhow::Result<bool> {
        let row = sqlx::query(
            r#"UPDATE user_sessions
               SET workspace_id = $2
               WHERE id = $1 AND revoked_at IS NULL
               RETURNING id"#,
        )
        .bind(session_id)
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.is_some())
    }

    async fn touch(&self, session_id: Uuid) -> anyhow::Result<()> {
        sqlx::query("UPDATE user_sessions SET last_seen_at = now() WHERE id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<UserSessionRecord>> {
        let rows = sqlx::query(
            r#"SELECT id, user_id, workspace_id, user_agent, ip_address, remember_me,
                       created_at, last_seen_at, expires_at, revoked_at
               FROM user_sessions
               WHERE user_id = $1
               ORDER BY last_seen_at DESC"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Self::map_record).collect())
    }

    async fn find_by_id(&self, session_id: Uuid) -> anyhow::Result<Option<UserSessionRecord>> {
        let row = sqlx::query(
            r#"SELECT id, user_id, workspace_id, user_agent, ip_address, remember_me,
                       created_at, last_seen_at, expires_at, revoked_at
               FROM user_sessions
               WHERE id = $1
               LIMIT 1"#,
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Self::map_record))
    }

    async fn revoke(&self, session_id: Uuid) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            r#"UPDATE user_sessions
               SET revoked_at = now()
               WHERE id = $1 AND revoked_at IS NULL"#,
        )
        .bind(session_id)
        .execute(&self.pool)
        .await?;
        Ok(affected.rows_affected() > 0)
    }

    async fn revoke_by_digest(&self, token_digest: &str) -> anyhow::Result<bool> {
        let affected = sqlx::query(
            r#"UPDATE user_sessions
               SET revoked_at = now()
               WHERE token_digest = $1 AND revoked_at IS NULL"#,
        )
        .bind(token_digest)
        .execute(&self.pool)
        .await?;
        Ok(affected.rows_affected() > 0)
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> anyhow::Result<()> {
        sqlx::query(
            r#"UPDATE user_sessions
               SET revoked_at = now()
               WHERE user_id = $1 AND revoked_at IS NULL"#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_expired(&self, before: DateTime<Utc>, batch_size: i64) -> anyhow::Result<u64> {
        let rows = sqlx::query(
            r#"WITH expired AS (
                    SELECT id
                    FROM user_sessions
                    WHERE expires_at < $1
                    ORDER BY expires_at ASC
                    LIMIT $2
                )
                DELETE FROM user_sessions
                WHERE id IN (SELECT id FROM expired)
                RETURNING 1"#,
        )
        .bind(before)
        .bind(batch_size)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.len() as u64)
    }
}
