//! PostgreSQL session repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::encryption::DeviceId;
use domain::identity::{Session, SessionId, SessionRepository, UserId};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL session repository
#[derive(Clone)]
pub struct PgSessionRepository {
    pool: PgPool,
}

impl PgSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
#[error("database error: {0}")]
pub struct PgSessionRepositoryError(#[from] sqlx::Error);

/// Database row for session
#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    device_id: Option<Uuid>,
    token_hash: String,
    remember_me: bool,
    is_recovery: bool,
    ip_address: Option<String>,
    user_agent: Option<String>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

impl From<SessionRow> for Session {
    fn from(row: SessionRow) -> Self {
        Self {
            id: SessionId::from_uuid(row.id),
            user_id: UserId::from_uuid(row.user_id),
            device_id: row.device_id.map(DeviceId::from_uuid),
            token_hash: row.token_hash,
            remember_me: row.remember_me,
            is_recovery: row.is_recovery,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            expires_at: row.expires_at,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl SessionRepository for PgSessionRepository {
    type Error = PgSessionRepositoryError;

    async fn find_by_id(&self, id: SessionId) -> Result<Option<Session>, Self::Error> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, user_id, device_id, token_hash, remember_me, is_recovery, ip_address, user_agent, expires_at, created_at
            FROM sessions
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Session::from))
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>, Self::Error> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, user_id, device_id, token_hash, remember_me, is_recovery, ip_address, user_agent, expires_at, created_at
            FROM sessions
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Session::from))
    }

    async fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<Session>, Self::Error> {
        let rows = sqlx::query_as::<_, SessionRow>(
            r#"
            SELECT id, user_id, device_id, token_hash, remember_me, is_recovery, ip_address, user_agent, expires_at, created_at
            FROM sessions
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Session::from).collect())
    }

    async fn save(&self, session: &Session) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO sessions (id, user_id, device_id, token_hash, remember_me, is_recovery, ip_address, user_agent, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (id) DO UPDATE SET
                expires_at = EXCLUDED.expires_at,
                device_id = EXCLUDED.device_id
            "#,
        )
        .bind(session.id.as_uuid())
        .bind(session.user_id.as_uuid())
        .bind(session.device_id.map(|d| d.as_uuid()))
        .bind(&session.token_hash)
        .bind(session.remember_me)
        .bind(session.is_recovery)
        .bind(&session.ip_address)
        .bind(&session.user_agent)
        .bind(session.expires_at)
        .bind(session.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: SessionId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: UserId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64, Self::Error> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}
