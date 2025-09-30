use async_trait::async_trait;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DocSnapshot {
    pub version: i64,
    pub snapshot: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DocUpdate {
    pub seq: i64,
    pub update: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StreamFrame {
    pub id: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DocumentRecord {
    pub doc_type: String,
    pub path: Option<String>,
    pub title: String,
    pub owner_id: Option<Uuid>,
}

#[async_trait]
pub trait DocStateReader: Send + Sync {
    async fn latest_snapshot(&self, doc_id: &Uuid) -> anyhow::Result<Option<DocSnapshot>>;

    async fn updates_since(&self, doc_id: &Uuid, from_seq: i64) -> anyhow::Result<Vec<DocUpdate>>;

    async fn document_record(&self, doc_id: &Uuid) -> anyhow::Result<Option<DocumentRecord>>;
}

#[async_trait]
pub trait RealtimeBacklogReader: Send + Sync {
    async fn read_update_backlog(
        &self,
        doc_id: &str,
        last_stream_id: Option<&str>,
    ) -> anyhow::Result<Vec<StreamFrame>>;

    async fn read_awareness_backlog(
        &self,
        doc_id: &str,
        last_stream_id: Option<&str>,
    ) -> anyhow::Result<Vec<StreamFrame>>;
}
