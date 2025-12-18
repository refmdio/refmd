use async_trait::async_trait;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::plugins::ports::plugin_installation_repository::{
    PluginInstallation, PluginInstallationRepository,
};
use domain::plugins::scope::{PluginInstallationStatus, PluginScope};

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
        workspace_id: Uuid,
        plugin_id: &str,
        version: &str,
        scope: PluginScope,
        origin_url: Option<&str>,
        status: PluginInstallationStatus,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO plugin_installations
               (workspace_id, plugin_id, version, scope, origin_url, status)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (workspace_id, plugin_id)
               DO UPDATE SET
                 version = EXCLUDED.version,
                 scope = EXCLUDED.scope,
                 origin_url = EXCLUDED.origin_url,
                 status = EXCLUDED.status,
                 updated_at = now()"#,
        )
        .bind(workspace_id)
        .bind(plugin_id)
        .bind(version)
        .bind(scope.as_str())
        .bind(origin_url)
        .bind(status.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_for_workspace(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Vec<PluginInstallation>> {
        let rows = sqlx::query(
            r#"SELECT workspace_id, plugin_id, version, scope, origin_url, status, installed_at, updated_at
               FROM plugin_installations
               WHERE workspace_id = $1"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let scope_raw: String = row.get("scope");
            let status_raw: String = row.get("status");
            out.push(PluginInstallation {
                workspace_id: row.get("workspace_id"),
                plugin_id: row.get("plugin_id"),
                version: row.get("version"),
                scope: PluginScope::from_str(&scope_raw)
                    .ok_or_else(|| anyhow::anyhow!("invalid_plugin_scope"))?,
                origin_url: row.try_get("origin_url").ok(),
                status: PluginInstallationStatus::from_str(&status_raw)
                    .ok_or_else(|| anyhow::anyhow!("invalid_plugin_installation_status"))?,
                installed_at: row.get("installed_at"),
                updated_at: row.get("updated_at"),
            });
        }

        Ok(out)
    }

    async fn list_all(&self) -> anyhow::Result<Vec<PluginInstallation>> {
        let rows = sqlx::query(
            r#"SELECT workspace_id, plugin_id, version, scope, origin_url, status, installed_at, updated_at
               FROM plugin_installations"#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let scope_raw: String = row.get("scope");
            let status_raw: String = row.get("status");
            out.push(PluginInstallation {
                workspace_id: row.get("workspace_id"),
                plugin_id: row.get("plugin_id"),
                version: row.get("version"),
                scope: PluginScope::from_str(&scope_raw)
                    .ok_or_else(|| anyhow::anyhow!("invalid_plugin_scope"))?,
                origin_url: row.try_get("origin_url").ok(),
                status: PluginInstallationStatus::from_str(&status_raw)
                    .ok_or_else(|| anyhow::anyhow!("invalid_plugin_installation_status"))?,
                installed_at: row.get("installed_at"),
                updated_at: row.get("updated_at"),
            });
        }

        Ok(out)
    }

    async fn remove(&self, workspace_id: Uuid, plugin_id: &str) -> anyhow::Result<bool> {
        let res = sqlx::query(
            "DELETE FROM plugin_installations WHERE workspace_id = $1 AND plugin_id = $2",
        )
        .bind(workspace_id)
        .bind(plugin_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn remove_all_for_workspace(&self, workspace_id: Uuid) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM plugin_installations WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
