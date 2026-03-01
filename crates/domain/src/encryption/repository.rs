//! Encryption repository traits

use async_trait::async_trait;

use super::device::{Device, PendingDevice};
use super::device_keys::{DeviceEncryptedUMK, DeviceRevocationEvent};
use super::user_keys::{UserEncryptedIdentityKey, UserEncryptedMasterKey, UserIdentityPublicKey};
use super::value_objects::DeviceId;
use super::workspace_keys::{DocumentEncryptedKey, WorkspaceEncryptedKey, WorkspaceKekBackup};
use crate::document::DocumentId;
use crate::identity::UserId;
use crate::workspace::WorkspaceId;

/// Device repository trait
#[async_trait]
pub trait DeviceRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find device by ID
    async fn find_by_id(&self, id: DeviceId) -> Result<Option<Device>, Self::Error>;

    /// Find all devices for a user
    async fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<Device>, Self::Error>;

    /// Find all active (non-revoked) devices for a user
    async fn find_active_by_user_id(&self, user_id: UserId) -> Result<Vec<Device>, Self::Error>;

    /// Find an active (non-revoked) device by its signing public key (raw bytes)
    async fn find_active_by_signing_pub_key(
        &self,
        signing_pub_key: &[u8],
    ) -> Result<Option<Device>, Self::Error>;

    /// Save device
    async fn save(&self, device: &Device) -> Result<(), Self::Error>;

    /// Delete device
    async fn delete(&self, id: DeviceId) -> Result<(), Self::Error>;
}

/// Pending device repository trait
#[async_trait]
pub trait PendingDeviceRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find pending device by ID
    async fn find_by_id(&self, id: DeviceId) -> Result<Option<PendingDevice>, Self::Error>;

    /// Find all pending devices for a user
    async fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<PendingDevice>, Self::Error>;

    /// Save pending device
    async fn save(&self, device: &PendingDevice) -> Result<(), Self::Error>;

    /// Delete pending device
    async fn delete(&self, id: DeviceId) -> Result<(), Self::Error>;
}

/// User Identity public key repository trait
#[async_trait]
pub trait UserIdentityPublicKeyRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find by user ID
    async fn find_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Option<UserIdentityPublicKey>, Self::Error>;

    /// Save
    async fn save(&self, key: &UserIdentityPublicKey) -> Result<(), Self::Error>;

    /// Delete
    async fn delete(&self, user_id: UserId) -> Result<(), Self::Error>;
}

/// User Encrypted Master Key repository trait
#[async_trait]
pub trait UserEncryptedMasterKeyRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find by user ID
    async fn find_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Option<UserEncryptedMasterKey>, Self::Error>;

    /// Save
    async fn save(&self, key: &UserEncryptedMasterKey) -> Result<(), Self::Error>;

    /// Delete
    async fn delete(&self, user_id: UserId) -> Result<(), Self::Error>;
}

/// User Encrypted Identity Key repository trait
#[async_trait]
pub trait UserEncryptedIdentityKeyRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find by user ID
    async fn find_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Option<UserEncryptedIdentityKey>, Self::Error>;

    /// Save
    async fn save(&self, key: &UserEncryptedIdentityKey) -> Result<(), Self::Error>;

    /// Delete
    async fn delete(&self, user_id: UserId) -> Result<(), Self::Error>;
}

/// Workspace Encrypted Key (KEK) repository trait
#[async_trait]
pub trait WorkspaceEncryptedKeyRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find all keys for a workspace
    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceEncryptedKey>, Self::Error>;

    /// Find keys for a specific user's device in a workspace
    async fn find_by_workspace_and_device(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        device_id: DeviceId,
    ) -> Result<Vec<WorkspaceEncryptedKey>, Self::Error>;

    /// Find active key for a device
    async fn find_active_by_device(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        device_id: DeviceId,
    ) -> Result<Option<WorkspaceEncryptedKey>, Self::Error>;

    /// Save
    async fn save(&self, key: &WorkspaceEncryptedKey) -> Result<(), Self::Error>;

    /// Delete all keys for a user in a workspace
    async fn delete_by_workspace_and_user(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> Result<(), Self::Error>;
}

/// Document Encrypted Key (DEK) repository trait
#[async_trait]
pub trait DocumentEncryptedKeyRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find all keys for a document
    async fn find_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Vec<DocumentEncryptedKey>, Self::Error>;

    /// Find active key for a document
    async fn find_active_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Option<DocumentEncryptedKey>, Self::Error>;

    /// Save
    async fn save(&self, key: &DocumentEncryptedKey) -> Result<(), Self::Error>;

    /// Delete all keys for a document
    async fn delete_by_document_id(&self, document_id: DocumentId) -> Result<(), Self::Error>;
}

/// Device Revocation Event repository trait
#[async_trait]
pub trait DeviceRevocationEventRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find by user and device
    async fn find_by_user_and_device(
        &self,
        user_id: UserId,
        device_id: DeviceId,
    ) -> Result<Option<DeviceRevocationEvent>, Self::Error>;

    /// Find all revocation events for a user
    async fn find_by_user_id(
        &self,
        user_id: UserId,
    ) -> Result<Vec<DeviceRevocationEvent>, Self::Error>;

    /// Save
    async fn save(&self, event: &DeviceRevocationEvent) -> Result<(), Self::Error>;
}

/// Workspace KEK Backup repository trait (KEK encrypted with UMK)
#[async_trait]
pub trait WorkspaceKekBackupRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find active backup for a workspace and user
    async fn find_active_by_workspace_and_user(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
    ) -> Result<Option<WorkspaceKekBackup>, Self::Error>;

    /// Save backup (deactivates existing active backup, then inserts)
    async fn save(&self, backup: &WorkspaceKekBackup) -> Result<(), Self::Error>;

    /// Find max key_version for a workspace (for kek_version validation)
    async fn find_max_key_version(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<i32>, Self::Error>;
}

/// Device Encrypted UMK repository trait
#[async_trait]
pub trait DeviceEncryptedUMKRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find by user and device
    async fn find_by_user_and_device(
        &self,
        user_id: UserId,
        device_id: DeviceId,
    ) -> Result<Option<DeviceEncryptedUMK>, Self::Error>;

    /// Save
    async fn save(&self, umk: &DeviceEncryptedUMK) -> Result<(), Self::Error>;

    /// Delete
    async fn delete(&self, user_id: UserId, device_id: DeviceId) -> Result<(), Self::Error>;

    /// Delete all for a user
    async fn delete_by_user_id(&self, user_id: UserId) -> Result<(), Self::Error>;
}
