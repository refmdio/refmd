use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use domain::documents::doc_type::DocumentType;

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
    pub doc_type: DocumentType,
    pub path: Option<String>,
    pub desired_path: Option<String>,
    pub title: String,
    pub owner_id: Option<Uuid>,
    pub workspace_id: Uuid,
}

#[async_trait]
pub trait DocStateReader: Send + Sync {
    async fn latest_snapshot(&self, doc_id: &Uuid) -> PortResult<Option<DocSnapshot>>;

    async fn updates_since(&self, doc_id: &Uuid, from_seq: i64) -> PortResult<Vec<DocUpdate>>;

    async fn document_record(&self, doc_id: &Uuid) -> PortResult<Option<DocumentRecord>>;
}

#[async_trait]
pub trait RealtimeBacklogReader: Send + Sync {
    async fn read_update_backlog(
        &self,
        doc_id: &str,
        last_stream_id: Option<&str>,
    ) -> PortResult<Vec<StreamFrame>>;

    async fn read_awareness_backlog(
        &self,
        doc_id: &str,
        last_stream_id: Option<&str>,
    ) -> PortResult<Vec<StreamFrame>>;
}
