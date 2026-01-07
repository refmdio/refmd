use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::identity::dtos::{
    UserEncryptedMasterKeyDto, UserEncryptedPrivateKeyDto, UserPublicKeyDto,
};
use crate::identity::ports::user_keys_repository::UserKeysRepository;
use domain::identity::keys::{KdfParams, KdfType, KeyType};

pub struct UserKeysService {
    repo: Arc<dyn UserKeysRepository>,
}

#[async_trait]
pub trait UserKeysServiceFacade: Send + Sync {
    // Public keys
    async fn get_public_key(&self, user_id: Uuid) -> Result<Option<UserPublicKeyDto>, ServiceError>;
    async fn register_public_key(
        &self,
        user_id: Uuid,
        public_key: Vec<u8>,
        key_type: KeyType,
    ) -> Result<UserPublicKeyDto, ServiceError>;

    // Master key backup (for recovery)
    async fn get_master_key_backup(
        &self,
        user_id: Uuid,
    ) -> Result<Option<UserEncryptedMasterKeyDto>, ServiceError>;
    async fn store_master_key_backup(
        &self,
        user_id: Uuid,
        encrypted_key: Vec<u8>,
        salt: Vec<u8>,
        kdf_type: KdfType,
        kdf_params: KdfParams,
    ) -> Result<UserEncryptedMasterKeyDto, ServiceError>;

    // Private key (encrypted with UMK)
    async fn get_encrypted_private_key(
        &self,
        user_id: Uuid,
    ) -> Result<Option<UserEncryptedPrivateKeyDto>, ServiceError>;
    async fn store_encrypted_private_key(
        &self,
        user_id: Uuid,
        encrypted_private_key: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<UserEncryptedPrivateKeyDto, ServiceError>;

    // E2EE setup status
    async fn mark_e2ee_setup_completed(&self, user_id: Uuid) -> Result<(), ServiceError>;
    async fn is_e2ee_setup_completed(&self, user_id: Uuid) -> Result<bool, ServiceError>;
}

impl UserKeysService {
    pub fn new(repo: Arc<dyn UserKeysRepository>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl UserKeysServiceFacade for UserKeysService {
    async fn get_public_key(&self, user_id: Uuid) -> Result<Option<UserPublicKeyDto>, ServiceError> {
        let row = self
            .repo
            .get_public_key(user_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(row.map(|r| UserPublicKeyDto {
            user_id: r.user_id,
            public_key: r.public_key,
            key_type: r.key_type,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn register_public_key(
        &self,
        user_id: Uuid,
        public_key: Vec<u8>,
        key_type: KeyType,
    ) -> Result<UserPublicKeyDto, ServiceError> {
        let row = self
            .repo
            .upsert_public_key(user_id, &public_key, key_type)
            .await
            .map_err(ServiceError::from)?;
        Ok(UserPublicKeyDto {
            user_id: row.user_id,
            public_key: row.public_key,
            key_type: row.key_type,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_master_key_backup(
        &self,
        user_id: Uuid,
    ) -> Result<Option<UserEncryptedMasterKeyDto>, ServiceError> {
        let row = self
            .repo
            .get_encrypted_master_key(user_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(row.map(|r| UserEncryptedMasterKeyDto {
            user_id: r.user_id,
            encrypted_key: r.encrypted_key,
            salt: r.salt,
            kdf_type: r.kdf_type,
            kdf_params: r.kdf_params,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn store_master_key_backup(
        &self,
        user_id: Uuid,
        encrypted_key: Vec<u8>,
        salt: Vec<u8>,
        kdf_type: KdfType,
        kdf_params: KdfParams,
    ) -> Result<UserEncryptedMasterKeyDto, ServiceError> {
        let row = self
            .repo
            .upsert_encrypted_master_key(user_id, &encrypted_key, &salt, kdf_type, &kdf_params)
            .await
            .map_err(ServiceError::from)?;
        Ok(UserEncryptedMasterKeyDto {
            user_id: row.user_id,
            encrypted_key: row.encrypted_key,
            salt: row.salt,
            kdf_type: row.kdf_type,
            kdf_params: row.kdf_params,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_encrypted_private_key(
        &self,
        user_id: Uuid,
    ) -> Result<Option<UserEncryptedPrivateKeyDto>, ServiceError> {
        let row = self
            .repo
            .get_encrypted_private_key(user_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(row.map(|r| UserEncryptedPrivateKeyDto {
            user_id: r.user_id,
            encrypted_private_key: r.encrypted_private_key,
            nonce: r.nonce,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn store_encrypted_private_key(
        &self,
        user_id: Uuid,
        encrypted_private_key: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<UserEncryptedPrivateKeyDto, ServiceError> {
        let row = self
            .repo
            .upsert_encrypted_private_key(user_id, &encrypted_private_key, &nonce)
            .await
            .map_err(ServiceError::from)?;
        Ok(UserEncryptedPrivateKeyDto {
            user_id: row.user_id,
            encrypted_private_key: row.encrypted_private_key,
            nonce: row.nonce,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn mark_e2ee_setup_completed(&self, user_id: Uuid) -> Result<(), ServiceError> {
        self.repo
            .mark_e2ee_setup_completed(user_id)
            .await
            .map_err(ServiceError::from)
    }

    async fn is_e2ee_setup_completed(&self, user_id: Uuid) -> Result<bool, ServiceError> {
        self.repo
            .is_e2ee_setup_completed(user_id)
            .await
            .map_err(ServiceError::from)
    }
}
