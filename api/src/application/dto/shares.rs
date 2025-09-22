use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ActiveShareItemDto {
    pub id: Uuid,
    pub token: String,
    pub permission: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub document_id: Uuid,
    pub document_title: String,
    /// 'document' or 'folder'
    pub document_type: String,
    pub parent_share_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct ShareDocumentDto {
    pub id: Uuid,
    pub title: String,
    pub permission: String,
    pub content: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ShareBrowseTreeItemDto {
    pub id: Uuid,
    pub title: String,
    pub parent_id: Option<Uuid>,
    pub r#type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct ShareBrowseResponseDto {
    pub tree: Vec<ShareBrowseTreeItemDto>,
}
