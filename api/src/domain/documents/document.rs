use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Document {
    pub id: Uuid,
    pub title: String,
    pub parent_id: Option<Uuid>,
    pub doc_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub id: Uuid,
    pub title: String,
    pub doc_type: String,
    pub path: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct BacklinkInfo {
    pub document_id: Uuid,
    pub title: String,
    pub document_type: String,
    pub file_path: Option<String>,
    pub link_type: String,
    pub link_text: Option<String>,
    pub link_count: i64,
}

#[derive(Debug, Clone)]
pub struct OutgoingLink {
    pub document_id: Uuid,
    pub title: String,
    pub document_type: String,
    pub file_path: Option<String>,
    pub link_type: String,
    pub link_text: Option<String>,
    pub position_start: Option<i32>,
    pub position_end: Option<i32>,
}
