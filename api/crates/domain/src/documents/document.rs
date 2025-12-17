use uuid::Uuid;

use crate::documents::doc_type::DocumentType;
use crate::documents::path::{DesiredPath, Slug};
use crate::documents::title::Title;

#[derive(Debug, Clone)]
pub struct Document {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub owner_user_id: Option<Uuid>,
    pub workspace_id: Uuid,
    pub title: Title,
    pub parent_id: Option<Uuid>,
    pub doc_type: DocumentType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub created_by_plugin: Option<String>,
    pub slug: Slug,
    pub desired_path: DesiredPath,
    pub path: Option<String>,
    pub created_by: Option<Uuid>,
    pub archived_at: Option<chrono::DateTime<chrono::Utc>>,
    pub archived_by: Option<Uuid>,
    pub archived_parent_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub id: Uuid,
    pub title: Title,
    pub doc_type: DocumentType,
    pub path: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct BacklinkInfo {
    pub document_id: Uuid,
    pub title: Title,
    pub document_type: DocumentType,
    pub file_path: Option<String>,
    pub link_type: String,
    pub link_text: Option<String>,
    pub link_count: i64,
}

#[derive(Debug, Clone)]
pub struct OutgoingLink {
    pub document_id: Uuid,
    pub title: Title,
    pub document_type: DocumentType,
    pub file_path: Option<String>,
    pub link_type: String,
    pub link_text: Option<String>,
    pub position_start: Option<i32>,
    pub position_end: Option<i32>,
}
