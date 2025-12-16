use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocMeta {
    pub workspace_id: Uuid,
    pub doc_type: String,
    pub path: Option<String>,
    pub slug: String,
    pub desired_path: String,
    pub title: String,
    pub archived_at: Option<DateTime<Utc>>,
}

