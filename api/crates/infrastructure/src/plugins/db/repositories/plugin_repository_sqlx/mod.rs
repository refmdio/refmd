use async_trait::async_trait;
use serde_json::Value as JsonValue;
use sqlx::Row;
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::ports::errors::PortResult;
use application::plugins::ports::plugin_repository::{PluginRecord, PluginRepository};
use domain::plugins::scope::{PluginRecordScope, PluginScope};

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
        scope: PluginScope,
        scope_id: Option<Uuid>,
        key: &str,
    ) -> PortResult<Option<JsonValue>> {
        let out: anyhow::Result<Option<JsonValue>> = async {
            let row = sqlx::query(
                r#"SELECT value FROM plugin_kv WHERE plugin = $1 AND scope = $2 AND scope_id IS NOT DISTINCT FROM $3 AND key = $4"#,
            )
            .bind(plugin)
            .bind(scope.as_str())
            .bind(scope_id)
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
            Ok(row.and_then(|r| r.try_get::<JsonValue, _>("value").ok()))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn kv_set(
        &self,
        plugin: &str,
        scope: PluginScope,
        scope_id: Option<Uuid>,
        key: &str,
        value: &JsonValue,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                r#"INSERT INTO plugin_kv (plugin, scope, scope_id, key, value)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (plugin, scope, scope_id, key)
               DO UPDATE SET value = EXCLUDED.value, updated_at = now()"#,
            )
            .bind(plugin)
            .bind(scope.as_str())
            .bind(scope_id)
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn insert_record(
        &self,
        plugin: &str,
        scope: PluginRecordScope,
        scope_id: Uuid,
        kind: &str,
        data: &JsonValue,
    ) -> PortResult<PluginRecord> {
        let out: anyhow::Result<PluginRecord> = async {
            let row = sqlx::query(
                r#"INSERT INTO plugin_records (plugin, scope, scope_id, kind, data)
               VALUES ($1, $2, $3, $4, $5)
               RETURNING id, plugin, scope, scope_id, kind, data, created_at, updated_at"#,
            )
            .bind(plugin)
            .bind(scope.as_str())
            .bind(scope_id)
            .bind(kind)
            .bind(data)
            .fetch_one(&self.pool)
            .await?;
            let scope_raw: String = row.get("scope");
            let scope = PluginRecordScope::parse(&scope_raw)
                .ok_or_else(|| anyhow::anyhow!("invalid_plugin_record_scope"))?;
            Ok(PluginRecord {
                id: row.get("id"),
                plugin: row.get("plugin"),
                scope,
                scope_id: row.get("scope_id"),
                kind: row.get("kind"),
                data: row.get("data"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
        }
        .await;
        out.map_err(Into::into)
    }

    async fn update_record_data(
        &self,
        record_id: Uuid,
        patch: &JsonValue,
    ) -> PortResult<Option<PluginRecord>> {
        let out: anyhow::Result<Option<PluginRecord>> = async {
            let row = sqlx::query(
                r#"UPDATE plugin_records SET data = data || $2::jsonb, updated_at = now()
               WHERE id = $1
               RETURNING id, plugin, scope, scope_id, kind, data, created_at, updated_at"#,
            )
            .bind(record_id)
            .bind(patch)
            .fetch_optional(&self.pool)
            .await?;
            row.map(|r| {
                let scope_raw: String = r.get("scope");
                let scope = PluginRecordScope::parse(&scope_raw)
                    .ok_or_else(|| anyhow::anyhow!("invalid_plugin_record_scope"))?;
                Ok(PluginRecord {
                    id: r.get("id"),
                    plugin: r.get("plugin"),
                    scope,
                    scope_id: r.get("scope_id"),
                    kind: r.get("kind"),
                    data: r.get("data"),
                    created_at: r.get("created_at"),
                    updated_at: r.get("updated_at"),
                })
            })
            .transpose()
        }
        .await;
        out.map_err(Into::into)
    }

    async fn append_record_array_item(
        &self,
        record_id: Uuid,
        field: &str,
        item: &JsonValue,
        patch: &JsonValue,
    ) -> PortResult<Option<PluginRecord>> {
        let out: anyhow::Result<Option<PluginRecord>> = async {
            let row = sqlx::query(
                r#"UPDATE plugin_records
               SET data = jsonb_set(
                   data || $4::jsonb,
                   ARRAY[$2],
                   COALESCE(
                       CASE
                           WHEN jsonb_typeof(data -> $2) = 'array' THEN data -> $2
                           ELSE '[]'::jsonb
                       END,
                       '[]'::jsonb
                   ) || jsonb_build_array($3::jsonb),
                   true
               ),
               updated_at = now()
               WHERE id = $1
               RETURNING id, plugin, scope, scope_id, kind, data, created_at, updated_at"#,
            )
            .bind(record_id)
            .bind(field)
            .bind(item)
            .bind(patch)
            .fetch_optional(&self.pool)
            .await?;
            row.map(|r| {
                let scope_raw: String = r.get("scope");
                let scope = PluginRecordScope::parse(&scope_raw)
                    .ok_or_else(|| anyhow::anyhow!("invalid_plugin_record_scope"))?;
                Ok(PluginRecord {
                    id: r.get("id"),
                    plugin: r.get("plugin"),
                    scope,
                    scope_id: r.get("scope_id"),
                    kind: r.get("kind"),
                    data: r.get("data"),
                    created_at: r.get("created_at"),
                    updated_at: r.get("updated_at"),
                })
            })
            .transpose()
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_record(&self, record_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let res = sqlx::query("DELETE FROM plugin_records WHERE id = $1")
                .bind(record_id)
                .execute(&self.pool)
                .await?;
            Ok(res.rows_affected() > 0)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn get_record(&self, record_id: Uuid) -> PortResult<Option<PluginRecord>> {
        let out: anyhow::Result<Option<PluginRecord>> = async {
            let row = sqlx::query(
                r#"SELECT id, plugin, scope, scope_id, kind, data, created_at, updated_at
               FROM plugin_records WHERE id = $1"#,
            )
            .bind(record_id)
            .fetch_optional(&self.pool)
            .await?;
            row.map(|r| {
                let scope_raw: String = r.get("scope");
                let scope = PluginRecordScope::parse(&scope_raw)
                    .ok_or_else(|| anyhow::anyhow!("invalid_plugin_record_scope"))?;
                Ok(PluginRecord {
                    id: r.get("id"),
                    plugin: r.get("plugin"),
                    scope,
                    scope_id: r.get("scope_id"),
                    kind: r.get("kind"),
                    data: r.get("data"),
                    created_at: r.get("created_at"),
                    updated_at: r.get("updated_at"),
                })
            })
            .transpose()
        }
        .await;
        out.map_err(Into::into)
    }

    async fn list_records(
        &self,
        plugin: &str,
        scope: PluginRecordScope,
        scope_id: Uuid,
        kind: &str,
        limit: i64,
        offset: i64,
    ) -> PortResult<Vec<PluginRecord>> {
        let out: anyhow::Result<Vec<PluginRecord>> = async {
            let rows = sqlx::query(
                r#"SELECT id, plugin, scope, scope_id, kind, data, created_at, updated_at
               FROM plugin_records
               WHERE plugin = $1 AND scope = $2 AND scope_id = $3 AND kind = $4
               ORDER BY COALESCE((data->>'pinned')::boolean,false) DESC, created_at DESC
               LIMIT $5 OFFSET $6"#,
            )
            .bind(plugin)
            .bind(scope.as_str())
            .bind(scope_id)
            .bind(kind)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let scope_raw: String = r.get("scope");
                let parsed_scope = PluginRecordScope::parse(&scope_raw)
                    .ok_or_else(|| anyhow::anyhow!("invalid_plugin_record_scope"))?;
                out.push(PluginRecord {
                    id: r.get("id"),
                    plugin: r.get("plugin"),
                    scope: parsed_scope,
                    scope_id: r.get("scope_id"),
                    kind: r.get("kind"),
                    data: r.get("data"),
                    created_at: r.get("created_at"),
                    updated_at: r.get("updated_at"),
                });
            }
            Ok(out)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_scoped_kv(&self, scope: PluginScope, scope_ids: &[Uuid]) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            if scope_ids.is_empty() {
                return Ok(());
            }
            sqlx::query("DELETE FROM plugin_kv WHERE scope = $1 AND scope_id = ANY($2)")
                .bind(scope.as_str())
                .bind(scope_ids)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn delete_scoped_records(
        &self,
        scope: PluginRecordScope,
        scope_ids: &[Uuid],
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            if scope_ids.is_empty() {
                return Ok(());
            }
            sqlx::query("DELETE FROM plugin_records WHERE scope = $1 AND scope_id = ANY($2)")
                .bind(scope.as_str())
                .bind(scope_ids)
                .execute(&self.pool)
                .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }
}
