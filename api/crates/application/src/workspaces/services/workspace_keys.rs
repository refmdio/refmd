use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::workspaces::dtos::WorkspaceEncryptedKeyDto;
use crate::workspaces::ports::workspace_keys_repository::{
    WorkspaceEncryptedKeyRow, WorkspaceKeysRepository,
};

pub struct WorkspaceKeysService {
    repo: Arc<dyn WorkspaceKeysRepository>,
}

#[async_trait]
pub trait WorkspaceKeysServiceFacade: Send + Sync {
    /// Get the encrypted KEK for the current user in a workspace
    async fn get_encrypted_kek(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkspaceEncryptedKeyDto>, ServiceError>;

    /// Store an encrypted KEK for a user (used when sharing workspace key)
    async fn store_encrypted_kek(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        encrypted_kek: Vec<u8>,
        key_version: i32,
    ) -> Result<WorkspaceEncryptedKeyDto, ServiceError>;

    /// Get all encrypted KEKs for a workspace (for key rotation)
    async fn list_encrypted_keks(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceEncryptedKeyDto>, ServiceError>;

    /// Get the current key version for a workspace
    async fn get_current_key_version(&self, workspace_id: Uuid) -> Result<Option<i32>, ServiceError>;

    /// Delete a specific key version (for key rotation cleanup)
    async fn delete_key_version(
        &self,
        workspace_id: Uuid,
        key_version: i32,
    ) -> Result<u64, ServiceError>;

    /// Rotate workspace KEK for all members
    /// Returns the new key version and number of keys updated
    async fn rotate_keys(
        &self,
        workspace_id: Uuid,
        member_keys: Vec<(Uuid, Vec<u8>)>, // (user_id, encrypted_kek)
    ) -> Result<(i32, usize), ServiceError>;
}

impl WorkspaceKeysService {
    pub fn new(repo: Arc<dyn WorkspaceKeysRepository>) -> Self {
        Self { repo }
    }
}

fn row_to_dto(row: WorkspaceEncryptedKeyRow) -> WorkspaceEncryptedKeyDto {
    WorkspaceEncryptedKeyDto {
        id: row.id,
        workspace_id: row.workspace_id,
        user_id: row.user_id,
        encrypted_kek: row.encrypted_kek,
        key_version: row.key_version,
        created_at: row.created_at,
    }
}

#[async_trait]
impl WorkspaceKeysServiceFacade for WorkspaceKeysService {
    async fn get_encrypted_kek(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<WorkspaceEncryptedKeyDto>, ServiceError> {
        let row = self
            .repo
            .get_encrypted_kek(workspace_id, user_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(row.map(row_to_dto))
    }

    async fn store_encrypted_kek(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        encrypted_kek: Vec<u8>,
        key_version: i32,
    ) -> Result<WorkspaceEncryptedKeyDto, ServiceError> {
        let row = self
            .repo
            .upsert_encrypted_kek(workspace_id, user_id, &encrypted_kek, key_version)
            .await
            .map_err(ServiceError::from)?;
        Ok(row_to_dto(row))
    }

    async fn list_encrypted_keks(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceEncryptedKeyDto>, ServiceError> {
        let rows = self
            .repo
            .list_encrypted_keks(workspace_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(rows.into_iter().map(row_to_dto).collect())
    }

    async fn get_current_key_version(&self, workspace_id: Uuid) -> Result<Option<i32>, ServiceError> {
        self.repo
            .get_current_key_version(workspace_id)
            .await
            .map_err(ServiceError::from)
    }

    async fn delete_key_version(
        &self,
        workspace_id: Uuid,
        key_version: i32,
    ) -> Result<u64, ServiceError> {
        self.repo
            .delete_encrypted_kek_version(workspace_id, key_version)
            .await
            .map_err(ServiceError::from)
    }

    async fn rotate_keys(
        &self,
        workspace_id: Uuid,
        member_keys: Vec<(Uuid, Vec<u8>)>,
    ) -> Result<(i32, usize), ServiceError> {
        if member_keys.is_empty() {
            return Err(ServiceError::BadRequest("no_member_keys_provided"));
        }

        // Get current key version and increment
        let current_version = self
            .repo
            .get_current_key_version(workspace_id)
            .await
            .map_err(ServiceError::from)?;
        let new_version = current_version.unwrap_or(0) + 1;

        // Store encrypted KEKs for all members with new version
        let mut updated_count = 0;
        for (user_id, encrypted_kek) in member_keys {
            self.repo
                .upsert_encrypted_kek(workspace_id, user_id, &encrypted_kek, new_version)
                .await
                .map_err(ServiceError::from)?;
            updated_count += 1;
        }

        Ok((new_version, updated_count))
    }
}
