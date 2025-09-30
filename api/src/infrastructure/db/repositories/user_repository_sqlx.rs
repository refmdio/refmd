use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::user_repository::{UserRepository, UserRow};
use crate::infrastructure::db::PgPool;

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
        email: &str,
        name: &str,
        password_hash: &str,
    ) -> anyhow::Result<UserRow> {
        let row = sqlx::query(
            r#"INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3)
               RETURNING id, email, name, password_hash"#,
        )
        .bind(email)
        .bind(name)
        .bind(password_hash)
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

    async fn delete_user(&self, id: Uuid) -> anyhow::Result<bool> {
        let res = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }
}
