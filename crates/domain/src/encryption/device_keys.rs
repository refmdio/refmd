//! Device-related key entities

use chrono::{DateTime, Utc};

use super::value_objects::DeviceId;
use crate::identity::UserId;

/// Device Revocation Event
/// Signed by Identity key to prevent server tampering.
#[derive(Debug, Clone)]
pub struct DeviceRevocationEvent {
    pub user_id: UserId,
    /// ID of the revoked device
    pub device_id: DeviceId,
    /// Revocation timestamp (Unix milliseconds)
    pub revoked_at: i64,
    /// Device that performed the revocation
    pub revoked_by_device_id: DeviceId,
    /// Signature by user's Identity signing key
    pub signature: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

impl DeviceRevocationEvent {
    /// Create a new revocation event with client-provided timestamp.
    /// The `revoked_at` should match what was signed by the client.
    pub fn new(
        user_id: UserId,
        device_id: DeviceId,
        revoked_by_device_id: DeviceId,
        revoked_at: i64,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            user_id,
            device_id,
            revoked_at,
            revoked_by_device_id,
            signature,
            created_at: Utc::now(),
        }
    }

    /// Get revocation timestamp as DateTime
    pub fn revoked_at_datetime(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.revoked_at).unwrap_or(self.created_at)
    }

    /// Get the data that should be signed
    /// Format: user_id || device_id || revoked_at || revoked_by_device_id
    pub fn signature_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(self.user_id.as_uuid().as_bytes());
        payload.extend_from_slice(self.device_id.as_uuid().as_bytes());
        payload.extend_from_slice(&self.revoked_at.to_be_bytes());
        payload.extend_from_slice(self.revoked_by_device_id.as_uuid().as_bytes());
        payload
    }
}

/// Device Encrypted UMK
/// UMK distributed to approved devices via ECDH key exchange.
/// Only created for verified (non-pending) devices.
#[derive(Debug, Clone)]
pub struct DeviceEncryptedUMK {
    pub user_id: UserId,
    /// Receiving device ID
    pub device_id: DeviceId,
    /// Sending device ID (for HKDF info construction)
    pub sender_device_id: DeviceId,
    /// UMK encrypted with shared secret derived from ECDH
    pub encrypted_umk: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

impl DeviceEncryptedUMK {
    pub fn new(
        user_id: UserId,
        device_id: DeviceId,
        sender_device_id: DeviceId,
        encrypted_umk: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self {
            user_id,
            device_id,
            sender_device_id,
            encrypted_umk,
            nonce,
            created_at: Utc::now(),
        }
    }
}
