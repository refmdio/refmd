use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use domain::identity::keys::{KdfParams, KdfType, KeyType};

#[derive(Debug, Clone)]
pub struct UserPublicKeyRow {
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub key_type: KeyType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct UserEncryptedMasterKeyRow {
    pub user_id: Uuid,
    pub encrypted_key: Vec<u8>,
    pub salt: Vec<u8>,
    pub kdf_type: KdfType,
    pub kdf_params: KdfParams,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct UserEncryptedPrivateKeyRow {
    pub user_id: Uuid,
    pub encrypted_private_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait UserKeysRepository: Send + Sync {
    // Public keys
    async fn get_public_key(&self, user_id: Uuid) -> PortResult<Option<UserPublicKeyRow>>;
    async fn upsert_public_key(
        &self,
        user_id: Uuid,
        public_key: &[u8],
        key_type: KeyType,
    ) -> PortResult<UserPublicKeyRow>;

    // Encrypted master keys (for recovery)
    async fn get_encrypted_master_key(
        &self,
        user_id: Uuid,
    ) -> PortResult<Option<UserEncryptedMasterKeyRow>>;
    async fn upsert_encrypted_master_key(
        &self,
        user_id: Uuid,
        encrypted_key: &[u8],
        salt: &[u8],
        kdf_type: KdfType,
        kdf_params: &KdfParams,
    ) -> PortResult<UserEncryptedMasterKeyRow>;

    // Encrypted private keys
    async fn get_encrypted_private_key(
        &self,
        user_id: Uuid,
    ) -> PortResult<Option<UserEncryptedPrivateKeyRow>>;
    async fn upsert_encrypted_private_key(
        &self,
        user_id: Uuid,
        encrypted_private_key: &[u8],
        nonce: &[u8],
    ) -> PortResult<UserEncryptedPrivateKeyRow>;

    // E2EE setup status
    async fn mark_e2ee_setup_completed(&self, user_id: Uuid) -> PortResult<()>;
    async fn is_e2ee_setup_completed(&self, user_id: Uuid) -> PortResult<bool>;
}
