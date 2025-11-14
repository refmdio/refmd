use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

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
    pub user_id: Uuid,
    pub repo_path: String,
    pub backend: String,
    pub kind: StorageIngestKind,
    pub content_hash: Option<String>,
    pub payload: Option<Value>,
    pub attempts: i32,
}

#[async_trait]
pub trait StorageIngestQueue: Send + Sync {
    async fn enqueue_event(
        &self,
        user_id: Uuid,
        repo_path: &str,
        backend: &str,
        kind: StorageIngestKind,
        content_hash: Option<&str>,
        payload: Option<Value>,
    ) -> anyhow::Result<()>;

    async fn fetch_next_event(&self) -> anyhow::Result<Option<StorageIngestEvent>>;

    async fn complete_event(&self, event_id: i64) -> anyhow::Result<()>;

    async fn fail_event(&self, event_id: i64, error: &str) -> anyhow::Result<()>;
}
