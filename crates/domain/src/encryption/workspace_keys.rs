//! Workspace and Document encryption key entities

use chrono::{DateTime, Utc};

use crate::document::DocumentId;
use crate::identity::UserId;
use crate::workspace::WorkspaceId;
use super::value_objects::{DeviceId, KeyVersion};

/// Workspace Encrypted Key (KEK)
/// Encrypted with each member's device public key.
/// Supports key rotation with multiple versions.
#[derive(Debug, Clone)]
pub struct WorkspaceEncryptedKey {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// Device that sent/created this encrypted key (for HKDF info reconstruction)
    pub sender_device_id: DeviceId,
    pub key_version: KeyVersion,
    /// KEK encrypted with device's public key
    pub encrypted_kek: Vec<u8>,
    pub nonce: Vec<u8>,
    /// Whether this is the currently active key version
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl WorkspaceEncryptedKey {
    pub fn new(
        workspace_id: WorkspaceId,
        user_id: UserId,
        device_id: DeviceId,
        sender_device_id: DeviceId,
        key_version: KeyVersion,
        encrypted_kek: Vec<u8>,
        nonce: Vec<u8>,
        is_active: bool,
    ) -> Self {
        Self {
            workspace_id,
            user_id,
            device_id,
            sender_device_id,
            key_version,
            encrypted_kek,
            nonce,
            is_active,
            created_at: Utc::now(),
        }
    }

    /// Create initial KEK for workspace creator
    pub fn new_initial(
        workspace_id: WorkspaceId,
        user_id: UserId,
        device_id: DeviceId,
        encrypted_kek: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self::new(
            workspace_id,
            user_id,
            device_id,
            device_id, // sender is same device for initial
            KeyVersion::initial(),
            encrypted_kek,
            nonce,
            true,
        )
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

    /// Create initial DEK for new document
    pub fn new_initial(
        document_id: DocumentId,
        encrypted_dek: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self::new(
            document_id,
            KeyVersion::initial(),
            encrypted_dek,
            nonce,
            true,
        )
    }
}
