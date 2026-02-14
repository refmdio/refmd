//! PostgreSQL session repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::encryption::DeviceId;
use domain::identity::{Session, SessionId, SessionRepository, UserId};
use uuid::Uuid;

pg_repo_struct!(PgSessionRepository);
pg_repo_error!(PgSessionRepositoryError);

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
        let row = sqlx::query_as!(
            SessionRow,
            r#"
            SELECT id, user_id, device_id, token_hash, remember_me, is_recovery, ip_address, user_agent, expires_at, created_at
            FROM sessions
            WHERE id = $1
            "#,
            id.as_uuid()
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Session::from))
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>, Self::Error> {
        let row = sqlx::query_as!(
            SessionRow,
            r#"
            SELECT id, user_id, device_id, token_hash, remember_me, is_recovery, ip_address, user_agent, expires_at, created_at
            FROM sessions
            WHERE token_hash = $1
            "#,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Session::from))
    }

    async fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<Session>, Self::Error> {
        let rows = sqlx::query_as!(
            SessionRow,
            r#"
            SELECT id, user_id, device_id, token_hash, remember_me, is_recovery, ip_address, user_agent, expires_at, created_at
            FROM sessions
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id.as_uuid()
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Session::from).collect())
    }

    async fn save(&self, session: &Session) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            INSERT INTO sessions (id, user_id, device_id, token_hash, remember_me, is_recovery, ip_address, user_agent, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (id) DO UPDATE SET
                expires_at = EXCLUDED.expires_at,
                device_id = EXCLUDED.device_id
            "#,
            session.id.as_uuid(),
            session.user_id.as_uuid(),
            session.device_id.map(|d| d.as_uuid()) as Option<Uuid>,
            &session.token_hash,
            session.remember_me,
            session.is_recovery,
            session.ip_address.as_deref(),
            session.user_agent.as_deref(),
            session.expires_at,
            session.created_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: SessionId) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM sessions WHERE id = $1",
            id.as_uuid()
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: UserId) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM sessions WHERE user_id = $1",
            user_id.as_uuid()
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
