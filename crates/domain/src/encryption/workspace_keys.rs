//! Workspace and Document encryption key entities

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::identity::UserId;
use super::value_objects::{DeviceId, KeyVersion};

/// Workspace ID (placeholder until workspace domain is implemented)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceId(Uuid);

impl WorkspaceId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for WorkspaceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Document ID (placeholder until document domain is implemented)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DocumentId(Uuid);

impl DocumentId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for DocumentId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
