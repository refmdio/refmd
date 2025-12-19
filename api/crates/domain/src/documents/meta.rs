use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::documents::doc_type::DocumentType;
use crate::documents::path::{DesiredPath, Slug};
use crate::documents::title::Title;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocMeta {
    pub workspace_id: Uuid,
    pub doc_type: DocumentType,
    pub path: Option<String>,
    pub slug: Slug,
    pub desired_path: DesiredPath,
    pub title: Title,
    pub archived_at: Option<DateTime<Utc>>,
}
