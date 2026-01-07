use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct WorkspaceEncryptedKeyDto {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub encrypted_kek: Vec<u8>,
    pub key_version: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
