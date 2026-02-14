//! Workspace and Document encryption key entities

use chrono::{DateTime, Utc};

use super::value_objects::{DeviceId, KeyVersion};
use crate::document::DocumentId;
use crate::identity::UserId;
use crate::workspace::WorkspaceId;

/// Parameters for creating a new workspace encrypted key
#[derive(Debug, Clone)]
pub struct NewWorkspaceKeyParams {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub sender_device_id: DeviceId,
    pub key_version: KeyVersion,
    pub encrypted_kek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub is_active: bool,
}

/// Workspace Encrypted Key (KEK)
/// Encrypted with device public key or UMK.
/// Supports key rotation with multiple versions.
#[derive(Debug, Clone)]
pub struct WorkspaceEncryptedKey {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub sender_device_id: DeviceId,
    pub key_version: KeyVersion,
    pub encrypted_kek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl WorkspaceEncryptedKey {
    pub fn new(params: NewWorkspaceKeyParams) -> Self {
        Self {
            workspace_id: params.workspace_id,
            user_id: params.user_id,
            device_id: params.device_id,
            sender_device_id: params.sender_device_id,
            key_version: params.key_version,
            encrypted_kek: params.encrypted_kek,
            nonce: params.nonce,
            is_active: params.is_active,
            created_at: Utc::now(),
        }
    }

}

/// Parameters for creating a new workspace KEK backup (encrypted with UMK)
#[derive(Debug, Clone)]
pub struct NewWorkspaceKekBackupParams {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub key_version: KeyVersion,
    pub encrypted_kek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub is_active: bool,
}

/// Workspace KEK Backup
/// KEK encrypted with UMK for recovery (device-independent).
/// Unlike WorkspaceEncryptedKey which is per-device (ECDH), this is per-user (UMK).
#[derive(Debug, Clone)]
pub struct WorkspaceKekBackup {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub key_version: KeyVersion,
    pub encrypted_kek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl WorkspaceKekBackup {
    pub fn new(params: NewWorkspaceKekBackupParams) -> Self {
        Self {
            workspace_id: params.workspace_id,
            user_id: params.user_id,
            key_version: params.key_version,
            encrypted_kek: params.encrypted_kek,
            nonce: params.nonce,
            is_active: params.is_active,
            created_at: Utc::now(),
        }
    }
}

/// Document Encrypted Key (DEK)
/// Encrypted with workspace's KEK.
/// Supports key rotation with multiple versions.
#[derive(Debug, Clone)]
pub struct DocumentEncryptedKey {
    pub document_id: DocumentId,
    pub key_version: KeyVersion,
    /// DEK encrypted with KEK
    pub encrypted_dek: Vec<u8>,
    pub nonce: Vec<u8>,
    /// Whether this is the currently active key version
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl DocumentEncryptedKey {
    pub fn new(
        document_id: DocumentId,
        key_version: KeyVersion,
        encrypted_dek: Vec<u8>,
        nonce: Vec<u8>,
        is_active: bool,
    ) -> Self {
        Self {
            document_id,
            key_version,
            encrypted_dek,
            nonce,
            is_active,
            created_at: Utc::now(),
        }
    }

}
