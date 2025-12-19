use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use domain::storage::ingest_backend::StorageIngestBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageIngestKind {
    Upsert,
    Delete,
}

impl StorageIngestKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageIngestKind::Upsert => "upsert",
            StorageIngestKind::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StorageIngestEvent {
    pub id: i64,
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub repo_path: String,
    pub backend: StorageIngestBackend,
    pub kind: StorageIngestKind,
    pub content_hash: Option<String>,
    pub payload: Option<Value>,
    pub attempts: i32,
    pub locked_at: DateTime<Utc>,
    pub permission_snapshot: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StorageIngestQueueStats {
    pub pending: i64,
    pub locked: i64,
    pub distinct_users: i64,
    pub oldest_created_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait StorageIngestQueue: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn enqueue_event(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
        repo_path: &str,
        backend: StorageIngestBackend,
        kind: StorageIngestKind,
        content_hash: Option<&str>,
        payload: Option<Value>,
        permission_snapshot: &[String],
    ) -> PortResult<()>;

    async fn fetch_next_event(&self) -> PortResult<Option<StorageIngestEvent>>;

    async fn complete_event(&self, event_id: i64, locked_at: DateTime<Utc>) -> PortResult<()>;

    async fn fail_event(
        &self,
        event_id: i64,
        locked_at: DateTime<Utc>,
        error: &str,
    ) -> PortResult<()>;

    async fn stats(&self) -> PortResult<StorageIngestQueueStats>;
}
