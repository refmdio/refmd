use async_trait::async_trait;
use serde_json::Value as JsonValue;
use sqlx::Row;
use uuid::Uuid;

use crate::application::ports::plugin_repository::{PluginRecord, PluginRepository};
use crate::infrastructure::db::PgPool;

pub struct SqlxPluginRepository {
    pub pool: PgPool,
}

impl SqlxPluginRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PluginRepository for SqlxPluginRepository {
    async fn kv_get(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Option<Uuid>,
        key: &str,
    ) -> anyhow::Result<Option<JsonValue>> {
        let row = sqlx::query(
            r#"SELECT value FROM plugin_kv WHERE plugin = $1 AND scope = $2 AND scope_id IS NOT DISTINCT FROM $3 AND key = $4"#,
        )
        .bind(plugin)
        .bind(scope)
        .bind(scope_id)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.try_get::<JsonValue, _>("value").ok()))
    }

    async fn kv_set(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Option<Uuid>,
        key: &str,
        value: &JsonValue,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO plugin_kv (plugin, scope, scope_id, key, value)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (plugin, scope, scope_id, key)
               DO UPDATE SET value = EXCLUDED.value, updated_at = now()"#,
        )
        .bind(plugin)
        .bind(scope)
        .bind(scope_id)
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_record(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Uuid,
        kind: &str,
        data: &JsonValue,
    ) -> anyhow::Result<PluginRecord> {
        let row = sqlx::query(
            r#"INSERT INTO plugin_records (plugin, scope, scope_id, kind, data)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING id, plugin, scope, scope_id, kind, data, created_at, updated_at"#,
        )
        .bind(plugin)
        .bind(scope)
        .bind(scope_id)
        .bind(kind)
        .bind(data)
        .fetch_one(&self.pool)
        .await?;
        Ok(PluginRecord {
            id: row.get("id"),
            plugin: row.get("plugin"),
            scope: row.get("scope"),
            scope_id: row.get("scope_id"),
            kind: row.get("kind"),
            data: row.get("data"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    async fn update_record_data(
        &self,
        record_id: Uuid,
        patch: &JsonValue,
    ) -> anyhow::Result<Option<PluginRecord>> {
        let row = sqlx::query(
            r#"UPDATE plugin_records SET data = data || $2::jsonb, updated_at = now()
               WHERE id = $1
               RETURNING id, plugin, scope, scope_id, kind, data, created_at, updated_at"#,
        )
        .bind(record_id)
        .bind(patch)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| PluginRecord {
            id: r.get("id"),
            plugin: r.get("plugin"),
            scope: r.get("scope"),
            scope_id: r.get("scope_id"),
            kind: r.get("kind"),
            data: r.get("data"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    async fn delete_record(&self, record_id: Uuid) -> anyhow::Result<bool> {
        let res = sqlx::query("DELETE FROM plugin_records WHERE id = $1")
            .bind(record_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn get_record(&self, record_id: Uuid) -> anyhow::Result<Option<PluginRecord>> {
        let row = sqlx::query(
            r#"SELECT id, plugin, scope, scope_id, kind, data, created_at, updated_at
               FROM plugin_records WHERE id = $1"#,
        )
        .bind(record_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| PluginRecord {
            id: r.get("id"),
            plugin: r.get("plugin"),
            scope: r.get("scope"),
            scope_id: r.get("scope_id"),
            kind: r.get("kind"),
            data: r.get("data"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    async fn list_records(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Uuid,
        kind: &str,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<PluginRecord>> {
        let rows = sqlx::query(
            r#"SELECT id, plugin, scope, scope_id, kind, data, created_at, updated_at
               FROM plugin_records
               WHERE plugin = $1 AND scope = $2 AND scope_id = $3 AND kind = $4
               ORDER BY COALESCE((data->>'pinned')::boolean,false) DESC, created_at DESC
               LIMIT $5 OFFSET $6"#,
        )
        .bind(plugin)
        .bind(scope)
        .bind(scope_id)
        .bind(kind)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(PluginRecord {
                id: r.get("id"),
                plugin: r.get("plugin"),
                scope: r.get("scope"),
                scope_id: r.get("scope_id"),
                kind: r.get("kind"),
                data: r.get("data"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            });
        }
        Ok(out)
    }
}
