use uuid::Uuid;

use domain::identity::keys::{KdfParams, KdfType, KeyType};

#[derive(Debug, Clone)]
pub struct UserPublicKeyDto {
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub key_type: KeyType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct UserEncryptedMasterKeyDto {
    pub user_id: Uuid,
    pub encrypted_key: Vec<u8>,
    pub salt: Vec<u8>,
    pub kdf_type: KdfType,
    pub kdf_params: KdfParams,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct UserEncryptedPrivateKeyDto {
    pub user_id: Uuid,
    pub encrypted_private_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
