use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use application::identity::ports::user_shortcuts::user_shortcut_repository::{
    UserShortcutProfile, UserShortcutRepository,
};
use crate::core::db::PgPool;

pub struct SqlxUserShortcutRepository {
    pool: PgPool,
}

impl SqlxUserShortcutRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserShortcutRepository for SqlxUserShortcutRepository {
    async fn get_by_user(&self, user_id: Uuid) -> anyhow::Result<Option<UserShortcutProfile>> {
        let row = sqlx::query(
            r#"SELECT user_id, bindings, leader_key, updated_at
               FROM user_shortcuts
               WHERE user_id = $1
               LIMIT 1"#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| UserShortcutProfile {
            user_id: row.get("user_id"),
            bindings: row.get("bindings"),
            leader_key: row.try_get("leader_key").ok(),
            updated_at: row.get("updated_at"),
        }))
    }

    async fn upsert(
        &self,
        user_id: Uuid,
        bindings: serde_json::Value,
        leader_key: Option<String>,
    ) -> anyhow::Result<UserShortcutProfile> {
        let row = sqlx::query(
            r#"INSERT INTO user_shortcuts (user_id, bindings, leader_key, updated_at)
               VALUES ($1, $2, $3, now())
               ON CONFLICT (user_id)
               DO UPDATE SET
                 bindings = EXCLUDED.bindings,
                 leader_key = EXCLUDED.leader_key,
                 updated_at = now()
               RETURNING user_id, bindings, leader_key, updated_at"#,
        )
        .bind(user_id)
        .bind(bindings)
        .bind(leader_key)
        .fetch_one(&self.pool)
        .await?;

        Ok(UserShortcutProfile {
            user_id: row.get("user_id"),
            bindings: row.get("bindings"),
            leader_key: row.try_get("leader_key").ok(),
            updated_at: row.get("updated_at"),
        })
    }
}
