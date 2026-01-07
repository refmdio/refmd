use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct WorkspaceEncryptedKeyRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub encrypted_kek: Vec<u8>,
    pub key_version: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait WorkspaceKeysRepository: Send + Sync {
    /// Get the encrypted KEK for a user in a workspace
    async fn get_encrypted_kek(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
    ) -> PortResult<Option<WorkspaceEncryptedKeyRow>>;

    /// Get all encrypted KEKs for a workspace (for re-encryption during key rotation)
    async fn list_encrypted_keks(
        &self,
        workspace_id: Uuid,
    ) -> PortResult<Vec<WorkspaceEncryptedKeyRow>>;

    /// Store or update an encrypted KEK for a user
    async fn upsert_encrypted_kek(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        encrypted_kek: &[u8],
        key_version: i32,
    ) -> PortResult<WorkspaceEncryptedKeyRow>;

    /// Delete an encrypted KEK (when user is removed from workspace)
    async fn delete_encrypted_kek(&self, workspace_id: Uuid, user_id: Uuid) -> PortResult<bool>;

    /// Delete a specific key version for a workspace (for key rotation cleanup)
    async fn delete_encrypted_kek_version(
        &self,
        workspace_id: Uuid,
        key_version: i32,
    ) -> PortResult<u64>;

    /// Get the current key version for a workspace
    async fn get_current_key_version(&self, workspace_id: Uuid) -> PortResult<Option<i32>>;
}
