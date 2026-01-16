use uuid::Uuid;

use domain::identity::keys::KdfParams;

#[derive(Debug, Clone)]
pub struct DocumentEncryptedKeyDto {
    pub document_id: Uuid,
    pub encrypted_dek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct ShareEncryptedKeyDto {
    pub share_id: Uuid,
    pub encrypted_dek: Vec<u8>,
    pub salt: Option<Vec<u8>>,
    pub kdf_params: Option<KdfParams>,
    /// Share key encrypted with creator's KEK (for URL recovery by creator)
    pub creator_encrypted_share_key: Option<Vec<u8>>,
    /// Nonce for creator_encrypted_share_key
    pub creator_share_key_nonce: Option<Vec<u8>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ShareEncryptedKeyDto {
    pub fn is_password_protected(&self) -> bool {
        self.salt.is_some()
    }
}
