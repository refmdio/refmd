//! PostgreSQL user repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::identity::{Email, User, UserId, UserRepository};
use uuid::Uuid;

pg_repo_struct!(PgUserRepository);
pg_repo_error!(PgUserRepositoryError, CorruptedData(String));

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
        let row = sqlx::query_as!(
            UserRow,
            "SELECT id, email, name, encryption_setup_at, created_at, updated_at FROM users WHERE id = $1",
            id.as_uuid()
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_user()).transpose()
    }

    async fn find_by_ids(&self, ids: &[UserId]) -> Result<Vec<User>, Self::Error> {
        let uuids: Vec<Uuid> = ids.iter().map(|id| id.as_uuid()).collect();
        let rows = sqlx::query_as!(
            UserRow,
            "SELECT id, email, name, encryption_setup_at, created_at, updated_at FROM users WHERE id = ANY($1)",
            &uuids
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_user()).collect()
    }

    async fn find_by_email(&self, email: &Email) -> Result<Option<User>, Self::Error> {
        let row = sqlx::query_as!(
            UserRow,
            "SELECT id, email, name, encryption_setup_at, created_at, updated_at FROM users WHERE email = $1",
            email.as_str()
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_user()).transpose()
    }

    async fn email_exists(&self, email: &Email) -> Result<bool, Self::Error> {
        let result = sqlx::query_scalar!(
            r#"
            SELECT EXISTS(SELECT 1 FROM users WHERE email = $1) as "exists!"
            "#,
            email.as_str()
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn save(&self, user: &User) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            INSERT INTO users (id, email, name, encryption_setup_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (id) DO UPDATE SET
                email = EXCLUDED.email,
                name = EXCLUDED.name,
                encryption_setup_at = EXCLUDED.encryption_setup_at,
                updated_at = EXCLUDED.updated_at
            "#,
            user.id.as_uuid(),
            user.email.as_str(),
            &user.name,
            user.encryption_setup_at,
            user.created_at,
            user.updated_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: UserId) -> Result<(), Self::Error> {
        sqlx::query!("DELETE FROM users WHERE id = $1", id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
