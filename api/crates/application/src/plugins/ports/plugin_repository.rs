use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use domain::plugins::scope::{PluginRecordScope, PluginScope};

#[derive(Debug, Clone)]
pub struct PluginRecord {
    pub id: Uuid,
    pub plugin: String,
    pub scope: PluginRecordScope,
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
        scope: PluginScope,
        scope_id: Option<Uuid>,
        key: &str,
    ) -> PortResult<Option<JsonValue>>;
    async fn kv_set(
        &self,
        plugin: &str,
        scope: PluginScope,
        scope_id: Option<Uuid>,
        key: &str,
        value: &JsonValue,
    ) -> PortResult<()>;

    // Records
    async fn insert_record(
        &self,
        plugin: &str,
        scope: PluginRecordScope,
        scope_id: Uuid,
        kind: &str,
        data: &JsonValue,
    ) -> PortResult<PluginRecord>;

    async fn update_record_data(
        &self,
        record_id: Uuid,
        patch: &JsonValue,
    ) -> PortResult<Option<PluginRecord>>;

    async fn append_record_array_item(
        &self,
        record_id: Uuid,
        field: &str,
        item: &JsonValue,
        patch: &JsonValue,
    ) -> PortResult<Option<PluginRecord>>;

    async fn delete_record(&self, record_id: Uuid) -> PortResult<bool>;

    async fn get_record(&self, record_id: Uuid) -> PortResult<Option<PluginRecord>>;

    async fn list_records(
        &self,
        plugin: &str,
        scope: PluginRecordScope,
        scope_id: Uuid,
        kind: &str,
        limit: i64,
        offset: i64,
    ) -> PortResult<Vec<PluginRecord>>;

    async fn delete_scoped_kv(&self, scope: PluginScope, scope_ids: &[Uuid]) -> PortResult<()>;

    async fn delete_scoped_records(
        &self,
        scope: PluginRecordScope,
        scope_ids: &[Uuid],
    ) -> PortResult<()>;
}
