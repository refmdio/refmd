use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::documents::dtos::{DocumentEncryptedKeyDto, ShareEncryptedKeyDto};
use crate::documents::ports::document_keys_repository::DocumentKeysRepository;
use crate::documents::ports::share_keys_repository::ShareKeysRepository;
use domain::identity::keys::KdfParams;

pub struct DocumentKeysService {
    document_keys_repo: Arc<dyn DocumentKeysRepository>,
    share_keys_repo: Arc<dyn ShareKeysRepository>,
}

#[async_trait]
pub trait DocumentKeysServiceFacade: Send + Sync {
    // Document keys
    async fn get_document_key(
        &self,
        document_id: Uuid,
    ) -> Result<Option<DocumentEncryptedKeyDto>, ServiceError>;

    async fn store_document_key(
        &self,
        document_id: Uuid,
        encrypted_dek: Vec<u8>,
        nonce: Vec<u8>,
        key_version: i32,
    ) -> Result<DocumentEncryptedKeyDto, ServiceError>;

    // Share keys
    async fn get_share_key(
        &self,
        share_id: Uuid,
    ) -> Result<Option<ShareEncryptedKeyDto>, ServiceError>;

    async fn get_share_salt(&self, share_id: Uuid) -> Result<Option<Vec<u8>>, ServiceError>;

    async fn store_share_key(
        &self,
        share_id: Uuid,
        encrypted_dek: Vec<u8>,
    ) -> Result<ShareEncryptedKeyDto, ServiceError>;

    async fn store_password_protected_share_key(
        &self,
        share_id: Uuid,
        encrypted_dek: Vec<u8>,
        salt: Vec<u8>,
        kdf_params: KdfParams,
    ) -> Result<ShareEncryptedKeyDto, ServiceError>;

    /// Rotate document DEK
    /// Returns the new key version
    async fn rotate_document_key(
        &self,
        document_id: Uuid,
        encrypted_dek: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<i32, ServiceError>;
}

impl DocumentKeysService {
    pub fn new(
        document_keys_repo: Arc<dyn DocumentKeysRepository>,
        share_keys_repo: Arc<dyn ShareKeysRepository>,
    ) -> Self {
        Self {
            document_keys_repo,
            share_keys_repo,
        }
    }
}

#[async_trait]
impl DocumentKeysServiceFacade for DocumentKeysService {
    async fn get_document_key(
        &self,
        document_id: Uuid,
    ) -> Result<Option<DocumentEncryptedKeyDto>, ServiceError> {
        let row = self
            .document_keys_repo
            .get_encrypted_dek(document_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(row.map(|r| DocumentEncryptedKeyDto {
            document_id: r.document_id,
            encrypted_dek: r.encrypted_dek,
            nonce: r.nonce,
            key_version: r.key_version,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn store_document_key(
        &self,
        document_id: Uuid,
        encrypted_dek: Vec<u8>,
        nonce: Vec<u8>,
        key_version: i32,
    ) -> Result<DocumentEncryptedKeyDto, ServiceError> {
        let row = self
            .document_keys_repo
            .upsert_encrypted_dek(document_id, &encrypted_dek, &nonce, key_version)
            .await
            .map_err(ServiceError::from)?;
        Ok(DocumentEncryptedKeyDto {
            document_id: row.document_id,
            encrypted_dek: row.encrypted_dek,
            nonce: row.nonce,
            key_version: row.key_version,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_share_key(
        &self,
        share_id: Uuid,
    ) -> Result<Option<ShareEncryptedKeyDto>, ServiceError> {
        let row = self
            .share_keys_repo
            .get_encrypted_dek(share_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(row.map(|r| ShareEncryptedKeyDto {
            share_id: r.share_id,
            encrypted_dek: r.encrypted_dek,
            salt: r.salt,
            kdf_params: r.kdf_params,
            created_at: r.created_at,
        }))
    }

    async fn get_share_salt(&self, share_id: Uuid) -> Result<Option<Vec<u8>>, ServiceError> {
        self.share_keys_repo
            .get_salt(share_id)
            .await
            .map_err(ServiceError::from)
    }

    async fn store_share_key(
        &self,
        share_id: Uuid,
        encrypted_dek: Vec<u8>,
    ) -> Result<ShareEncryptedKeyDto, ServiceError> {
        let row = self
            .share_keys_repo
            .store_encrypted_dek(share_id, &encrypted_dek)
            .await
            .map_err(ServiceError::from)?;
        Ok(ShareEncryptedKeyDto {
            share_id: row.share_id,
            encrypted_dek: row.encrypted_dek,
            salt: row.salt,
            kdf_params: row.kdf_params,
            created_at: row.created_at,
        })
    }

    async fn store_password_protected_share_key(
        &self,
        share_id: Uuid,
        encrypted_dek: Vec<u8>,
        salt: Vec<u8>,
        kdf_params: KdfParams,
    ) -> Result<ShareEncryptedKeyDto, ServiceError> {
        let row = self
            .share_keys_repo
            .store_password_protected_dek(share_id, &encrypted_dek, &salt, &kdf_params)
            .await
            .map_err(ServiceError::from)?;
        Ok(ShareEncryptedKeyDto {
            share_id: row.share_id,
            encrypted_dek: row.encrypted_dek,
            salt: row.salt,
            kdf_params: row.kdf_params,
            created_at: row.created_at,
        })
    }

    async fn rotate_document_key(
        &self,
        document_id: Uuid,
        encrypted_dek: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<i32, ServiceError> {
        // Get current key version
        let current_version = self
            .document_keys_repo
            .get_encrypted_dek(document_id)
            .await
            .map_err(ServiceError::from)?
            .map(|r| r.key_version)
            .unwrap_or(0);

        // Increment version
        let new_version = current_version + 1;

        // Store new key with incremented version
        self.document_keys_repo
            .upsert_encrypted_dek(document_id, &encrypted_dek, &nonce, new_version)
            .await
            .map_err(ServiceError::from)?;

        Ok(new_version)
    }
}
