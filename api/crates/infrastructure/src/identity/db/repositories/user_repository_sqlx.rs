use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use application::identity::ports::user_repository::{UserRepository, UserRow};
use crate::core::db::PgPool;

pub struct SqlxUserRepository {
    pub pool: PgPool,
}

impl SqlxUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for SqlxUserRepository {
    async fn create_user(
        &self,
        id: Uuid,
        email: &str,
        name: &str,
        password_hash: Option<&str>,
        default_workspace_id: Uuid,
    ) -> anyhow::Result<UserRow> {
        let row = sqlx::query(
            r#"INSERT INTO users (id, email, name, password_hash, default_workspace_id)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING id, email, name, password_hash"#,
        )
        .bind(id)
        .bind(email)
        .bind(name)
        .bind(password_hash)
        .bind(default_workspace_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(UserRow {
            id: row.get("id"),
            email: row.get("email"),
            name: row.get("name"),
            password_hash: row.try_get("password_hash").ok(),
        })
    }

    async fn find_by_email(&self, email: &str) -> anyhow::Result<Option<UserRow>> {
        let row =
            sqlx::query(r#"SELECT id, email, name, password_hash FROM users WHERE email = $1"#)
                .bind(email)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| UserRow {
            id: r.get("id"),
            email: r.get("email"),
            name: r.get("name"),
            password_hash: r.try_get("password_hash").ok(),
        }))
    }

    async fn find_by_external_identity(
        &self,
        provider: &str,
        subject: &str,
    ) -> anyhow::Result<Option<UserRow>> {
        let row = sqlx::query(
            r#"SELECT u.id, u.email, u.name, u.password_hash
               FROM user_external_accounts a
               JOIN users u ON u.id = a.user_id
               WHERE a.provider = $1 AND a.subject = $2"#,
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| UserRow {
            id: r.get("id"),
            email: r.get("email"),
            name: r.get("name"),
            password_hash: r.try_get("password_hash").ok(),
        }))
    }

    async fn find_by_id(&self, id: Uuid) -> anyhow::Result<Option<UserRow>> {
        let row = sqlx::query(r#"SELECT id, email, name FROM users WHERE id = $1"#)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| UserRow {
            id: r.get("id"),
            email: r.get("email"),
            name: r.get("name"),
            password_hash: None,
        }))
    }

    async fn link_external_identity(
        &self,
        user_id: Uuid,
        provider: &str,
        subject: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO user_external_accounts (user_id, provider, subject)
               VALUES ($1, $2, $3)
               ON CONFLICT (provider, subject) DO UPDATE SET user_id = EXCLUDED.user_id"#,
        )
        .bind(user_id)
        .bind(provider)
        .bind(subject)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_user(&self, id: Uuid) -> anyhow::Result<bool> {
        let res = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_user_ids(&self) -> anyhow::Result<Vec<Uuid>> {
        let rows = sqlx::query("SELECT id FROM users")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get("id")).collect())
    }
}
