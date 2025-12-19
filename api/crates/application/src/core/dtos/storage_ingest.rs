use serde_json::Value;

use crate::core::ports::storage::storage_ingest_queue::StorageIngestKind;

#[derive(Debug, Clone)]
pub struct IngestBatch {
    pub events: Vec<IngestEvent>,
}

#[derive(Debug, Clone)]
pub struct IngestEvent {
    pub repo_path: String,
    pub kind: StorageIngestKind,
    pub backend: Option<String>,
    pub content_hash: Option<String>,
    pub payload: Option<Value>,
}
