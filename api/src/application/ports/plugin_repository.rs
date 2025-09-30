use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PluginRecord {
    pub id: Uuid,
    pub plugin: String,
    pub scope: String,
    pub scope_id: Uuid,
    pub kind: String,
    pub data: JsonValue,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait PluginRepository: Send + Sync {
    // KV
    async fn kv_get(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Option<Uuid>,
        key: &str,
    ) -> anyhow::Result<Option<JsonValue>>;
    async fn kv_set(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Option<Uuid>,
        key: &str,
        value: &JsonValue,
    ) -> anyhow::Result<()>;

    // Records
    async fn insert_record(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Uuid,
        kind: &str,
        data: &JsonValue,
    ) -> anyhow::Result<PluginRecord>;

    async fn update_record_data(
        &self,
        record_id: Uuid,
        patch: &JsonValue,
    ) -> anyhow::Result<Option<PluginRecord>>;

    async fn delete_record(&self, record_id: Uuid) -> anyhow::Result<bool>;

    async fn get_record(&self, record_id: Uuid) -> anyhow::Result<Option<PluginRecord>>;

    async fn list_records(
        &self,
        plugin: &str,
        scope: &str,
        scope_id: Uuid,
        kind: &str,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<PluginRecord>>;

    async fn delete_scoped_kv(&self, scope: &str, scope_ids: &[Uuid]) -> anyhow::Result<()>;

    async fn delete_scoped_records(&self, scope: &str, scope_ids: &[Uuid]) -> anyhow::Result<()>;
}
