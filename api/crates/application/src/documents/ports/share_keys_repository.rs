use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use domain::identity::keys::KdfParams;

#[derive(Debug, Clone)]
pub struct ShareEncryptedKeyRow {
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

#[async_trait]
pub trait ShareKeysRepository: Send + Sync {
    /// Get the encrypted DEK for a share
    async fn get_encrypted_dek(&self, share_id: Uuid) -> PortResult<Option<ShareEncryptedKeyRow>>;

    /// Get the salt for a password-protected share (for client-side KDF)
    async fn get_salt(&self, share_id: Uuid) -> PortResult<Option<Vec<u8>>>;

    /// Store an encrypted DEK for a share (URL fragment based, no password)
    async fn store_encrypted_dek(
        &self,
        share_id: Uuid,
        encrypted_dek: &[u8],
        creator_encrypted_share_key: Option<&[u8]>,
        creator_share_key_nonce: Option<&[u8]>,
    ) -> PortResult<ShareEncryptedKeyRow>;

    /// Store an encrypted DEK for a password-protected share
    async fn store_password_protected_dek(
        &self,
        share_id: Uuid,
        encrypted_dek: &[u8],
        salt: &[u8],
        kdf_params: &KdfParams,
        creator_encrypted_share_key: Option<&[u8]>,
        creator_share_key_nonce: Option<&[u8]>,
    ) -> PortResult<ShareEncryptedKeyRow>;

    /// Delete an encrypted DEK (when share is deleted)
    async fn delete_encrypted_dek(&self, share_id: Uuid) -> PortResult<bool>;
}
