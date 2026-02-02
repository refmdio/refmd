//! PostgreSQL user repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::identity::{Email, User, UserId, UserRepository};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL user repository
#[derive(Clone)]
pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgUserRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("corrupted data: invalid email in database: {0}")]
    CorruptedData(String),
}

/// Database row for user
#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    email: String,
    name: String,
    encryption_setup_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl UserRow {
    fn try_into_user(self) -> Result<User, PgUserRepositoryError> {
        let email = Email::new(&self.email)
            .map_err(|_| PgUserRepositoryError::CorruptedData(self.email.clone()))?;

        Ok(User {
            id: UserId::from_uuid(self.id),
            email,
            name: self.name,
            encryption_setup_at: self.encryption_setup_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    type Error = PgUserRepositoryError;

    async fn find_by_id(&self, id: UserId) -> Result<Option<User>, Self::Error> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, email, name, encryption_setup_at, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_user()).transpose()
    }

    async fn find_by_email(&self, email: &Email) -> Result<Option<User>, Self::Error> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, email, name, encryption_setup_at, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email.as_str())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_user()).transpose()
    }

    async fn email_exists(&self, email: &Email) -> Result<bool, Self::Error> {
        let result = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)
            "#,
        )
        .bind(email.as_str())
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn save(&self, user: &User) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO users (id, email, name, encryption_setup_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (id) DO UPDATE SET
                email = EXCLUDED.email,
                name = EXCLUDED.name,
                encryption_setup_at = EXCLUDED.encryption_setup_at,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(user.id.as_uuid())
        .bind(user.email.as_str())
        .bind(&user.name)
        .bind(user.encryption_setup_at)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: UserId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
