use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct DocumentEncryptedKeyRow {
    pub document_id: Uuid,
    pub encrypted_dek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait DocumentKeysRepository: Send + Sync {
    /// Get the encrypted DEK for a document
    async fn get_encrypted_dek(
        &self,
        document_id: Uuid,
    ) -> PortResult<Option<DocumentEncryptedKeyRow>>;

    /// Store or update an encrypted DEK for a document
    async fn upsert_encrypted_dek(
        &self,
        document_id: Uuid,
        encrypted_dek: &[u8],
        nonce: &[u8],
        key_version: i32,
    ) -> PortResult<DocumentEncryptedKeyRow>;

    /// Delete an encrypted DEK (when document is deleted)
    async fn delete_encrypted_dek(&self, document_id: Uuid) -> PortResult<bool>;
}
