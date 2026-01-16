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
pub struct ShareItemDto {
    pub id: Uuid,
    pub token: String,
    pub permission: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub document_id: Uuid,
    pub document_type: String,
    pub parent_share_id: Option<Uuid>,
    /// Share key encrypted with creator's KEK (for URL recovery)
    pub creator_encrypted_share_key: Option<Vec<u8>>,
    /// Nonce for creator_encrypted_share_key
    pub creator_share_key_nonce: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ShareMountDto {
    pub id: Uuid,
    pub token: String,
    pub target_document_id: Uuid,
    pub target_document_type: String,
    pub target_title: String,
    pub permission: String,
    pub parent_folder_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct ApplicableShareDto {
    pub token: String,
    pub permission: String,
    pub scope: String,
    pub excluded: bool,
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

#[derive(Debug, Clone)]
pub struct CreatedShareDto {
    pub share_id: Uuid,
    pub token: String,
    pub document_id: Uuid,
    pub document_type: String,
}
