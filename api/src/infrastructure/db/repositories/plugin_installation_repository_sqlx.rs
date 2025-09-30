use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::plugin_installation_repository::{
    PluginInstallation, PluginInstallationRepository,
};
use crate::infrastructure::db::PgPool;

pub struct SqlxPluginInstallationRepository {
    pub pool: PgPool,
}

impl SqlxPluginInstallationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PluginInstallationRepository for SqlxPluginInstallationRepository {
    async fn upsert(
        &self,
        user_id: Uuid,
        plugin_id: &str,
        version: &str,
        scope: &str,
        origin_url: Option<&str>,
        status: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO plugin_installations
               (user_id, plugin_id, version, scope, origin_url, status)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (user_id, plugin_id)
               DO UPDATE SET
                 version = EXCLUDED.version,
                 scope = EXCLUDED.scope,
                 origin_url = EXCLUDED.origin_url,
                 status = EXCLUDED.status,
                 updated_at = now()"#,
        )
        .bind(user_id)
        .bind(plugin_id)
        .bind(version)
        .bind(scope)
        .bind(origin_url)
        .bind(status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<PluginInstallation>> {
        let rows = sqlx::query(
            r#"SELECT user_id, plugin_id, version, scope, origin_url, status, installed_at, updated_at
               FROM plugin_installations
               WHERE user_id = $1"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(PluginInstallation {
                user_id: row.get("user_id"),
                plugin_id: row.get("plugin_id"),
                version: row.get("version"),
                scope: row.get("scope"),
                origin_url: row.try_get("origin_url").ok(),
                status: row.get("status"),
                installed_at: row.get("installed_at"),
                updated_at: row.get("updated_at"),
            });
        }

        Ok(out)
    }

    async fn remove(&self, user_id: Uuid, plugin_id: &str) -> anyhow::Result<bool> {
        let res =
            sqlx::query("DELETE FROM plugin_installations WHERE user_id = $1 AND plugin_id = $2")
                .bind(user_id)
                .bind(plugin_id)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn remove_all_for_user(&self, user_id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM plugin_installations WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
