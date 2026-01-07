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
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ShareEncryptedKeyDto {
    pub fn is_password_protected(&self) -> bool {
        self.salt.is_some()
    }
}
