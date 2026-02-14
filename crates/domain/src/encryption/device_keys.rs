//! Device-related key entities

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::value_objects::DeviceId;
use crate::identity::UserId;
use crate::signature::{SignatureAction, SignatureError, build_signature_message};

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

    /// Get the data that should be signed using JCS (JSON Canonicalization Scheme)
    ///
    /// Per spec: All signatures use the signature protocol format with
    /// canonicalized JSON including protocol, version, and action fields.
    pub fn signature_payload(&self) -> Result<Vec<u8>, SignatureError> {
        #[derive(Serialize)]
        struct RevocationPayload {
            device_id: String,
            revoked_at: i64,
            revoked_by_device_id: String,
            user_id: String,
        }

        build_signature_message(
            SignatureAction::DeviceRevocation,
            &RevocationPayload {
                user_id: self.user_id.as_uuid().to_string(),
                device_id: self.device_id.as_uuid().to_string(),
                revoked_at: self.revoked_at,
                revoked_by_device_id: self.revoked_by_device_id.as_uuid().to_string(),
            },
        )
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
