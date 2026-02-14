use chrono::{DateTime, Utc};

use domain::document::DocumentId;
use domain::encryption::{
    Device, DeviceEncryptedUMK, DeviceId, DocumentEncryptedKey, PendingDevice,
    WorkspaceEncryptedKey, WorkspaceKekBackup,
};
use domain::identity::UserId;
use domain::transfer_nonce::EncryptedTransferState;
use domain::workspace::WorkspaceId;

/// DTO for Device entity
#[derive(Debug, Clone)]
pub struct DeviceDto {
    pub id: DeviceId,
    pub user_id: UserId,
    pub name: String,
    pub device_type: String,
    pub ecdh_public_key: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    pub identity_signature: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub last_seen_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub is_revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<Device> for DeviceDto {
    fn from(d: Device) -> Self {
        let is_revoked = d.is_revoked();
        let device_type = d.device_type.as_str().to_string();
        Self {
            id: d.id,
            user_id: d.user_id,
            name: d.name,
            device_type,
            ecdh_public_key: d.ecdh_public_key,
            signing_public_key: d.signing_public_key,
            identity_signature: d.identity_signature,
            client_nonce: d.client_nonce,
            last_seen_at: d.last_seen_at,
            created_at: d.created_at,
            is_revoked,
            revoked_at: d.revoked_at,
        }
    }
}

/// DTO for PendingDevice entity
#[derive(Debug, Clone)]
pub struct PendingDeviceDto {
    pub id: DeviceId,
    pub user_id: UserId,
    pub name: String,
    pub device_type: String,
    pub ecdh_public_key: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_expired: bool,
}

impl From<PendingDevice> for PendingDeviceDto {
    fn from(d: PendingDevice) -> Self {
        let is_expired = d.is_expired();
        let device_type = d.device_type.as_str().to_string();
        Self {
            id: d.id,
            user_id: d.user_id,
            name: d.name,
            device_type,
            ecdh_public_key: d.ecdh_public_key,
            signing_public_key: d.signing_public_key,
            client_nonce: d.client_nonce,
            ip_address: d.ip_address,
            created_at: d.created_at,
            expires_at: d.expires_at,
            is_expired,
        }
    }
}

/// DTO for WorkspaceEncryptedKey entity
#[derive(Debug, Clone)]
pub struct WorkspaceEncryptedKeyDto {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub sender_device_id: DeviceId,
    pub key_version: i32,
    pub encrypted_kek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl From<WorkspaceEncryptedKey> for WorkspaceEncryptedKeyDto {
    fn from(k: WorkspaceEncryptedKey) -> Self {
        Self {
            workspace_id: k.workspace_id,
            user_id: k.user_id,
            device_id: k.device_id,
            sender_device_id: k.sender_device_id,
            key_version: k.key_version.as_i32(),
            encrypted_kek: k.encrypted_kek,
            nonce: k.nonce,
            is_active: k.is_active,
            created_at: k.created_at,
        }
    }
}

/// DTO for DocumentEncryptedKey entity
#[derive(Debug, Clone)]
pub struct DocumentEncryptedKeyDto {
    pub document_id: DocumentId,
    pub key_version: i32,
    pub encrypted_dek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl From<DocumentEncryptedKey> for DocumentEncryptedKeyDto {
    fn from(k: DocumentEncryptedKey) -> Self {
        Self {
            document_id: k.document_id,
            key_version: k.key_version.as_i32(),
            encrypted_dek: k.encrypted_dek,
            nonce: k.nonce,
            is_active: k.is_active,
            created_at: k.created_at,
        }
    }
}

/// DTO for WorkspaceKekBackup entity
#[derive(Debug, Clone)]
pub struct WorkspaceKekBackupDto {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub key_version: i32,
    pub encrypted_kek: Vec<u8>,
    pub nonce: Vec<u8>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl From<WorkspaceKekBackup> for WorkspaceKekBackupDto {
    fn from(b: WorkspaceKekBackup) -> Self {
        Self {
            workspace_id: b.workspace_id,
            user_id: b.user_id,
            key_version: b.key_version.as_i32(),
            encrypted_kek: b.encrypted_kek,
            nonce: b.nonce,
            is_active: b.is_active,
            created_at: b.created_at,
        }
    }
}

/// DTO for DeviceEncryptedUMK entity
#[derive(Debug, Clone)]
pub struct DeviceEncryptedUmkDto {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub sender_device_id: DeviceId,
    pub encrypted_umk: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

impl From<DeviceEncryptedUMK> for DeviceEncryptedUmkDto {
    fn from(u: DeviceEncryptedUMK) -> Self {
        Self {
            user_id: u.user_id,
            device_id: u.device_id,
            sender_device_id: u.sender_device_id,
            encrypted_umk: u.encrypted_umk,
            nonce: u.nonce,
            created_at: u.created_at,
        }
    }
}

/// DTO for EncryptedTransferState (trust state transfer)
#[derive(Debug, Clone)]
pub struct EncryptedTransferStateDto {
    /// XChaCha20-Poly1305 ciphertext
    pub ciphertext: Vec<u8>,
    /// XChaCha20-Poly1305 nonce (24 bytes)
    pub nonce: [u8; 24],
    /// Ed25519 signature (64 bytes)
    pub signature: [u8; 64],
    /// Device ID of the sender (existing device)
    pub sender_device_id: DeviceId,
}

impl From<EncryptedTransferState> for EncryptedTransferStateDto {
    fn from(s: EncryptedTransferState) -> Self {
        Self {
            ciphertext: s.ciphertext,
            nonce: s.nonce,
            signature: s.signature,
            sender_device_id: s.sender_device_id,
        }
    }
}

impl From<EncryptedTransferStateDto> for EncryptedTransferState {
    fn from(dto: EncryptedTransferStateDto) -> Self {
        Self {
            ciphertext: dto.ciphertext,
            nonce: dto.nonce,
            signature: dto.signature,
            sender_device_id: dto.sender_device_id,
        }
    }
}
