use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use application::core::ports::storage::storage_ingest_queue::StorageIngestKind;

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct IngestBatchRequest {
    pub events: Vec<IngestEventRequest>,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum IngestKindParam {
    Upsert,
    Delete,
}

impl From<IngestKindParam> for StorageIngestKind {
    fn from(value: IngestKindParam) -> Self {
        match value {
            IngestKindParam::Upsert => StorageIngestKind::Upsert,
            IngestKindParam::Delete => StorageIngestKind::Delete,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct IngestEventRequest {
    pub repo_path: String,
    pub kind: IngestKindParam,
    pub backend: Option<String>,
    pub content_hash: Option<String>,
    pub payload: Option<Value>,
}
