//! Device entity

use chrono::{DateTime, Utc};

use super::value_objects::{DeviceId, DeviceType, PublicKeyPair};
use crate::identity::UserId;

/// User device with cryptographic key pair
#[derive(Debug, Clone)]
pub struct Device {
    pub id: DeviceId,
    pub user_id: UserId,
    pub name: String,
    pub device_type: DeviceType,
    /// X25519 ECDH public key (32 bytes)
    pub ecdh_public_key: Vec<u8>,
    /// Ed25519 signing public key (32 bytes)
    pub signing_public_key: Vec<u8>,
    /// Signature from user's Identity signing key
    pub identity_signature: Vec<u8>,
    /// Client nonce for SAS verification (16 bytes)
    pub client_nonce: Vec<u8>,
    pub last_seen_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Device {
    /// Create a new device from a pending device after SAS verification
    pub fn from_pending(pending: PendingDevice, identity_signature: Vec<u8>) -> Self {
        let now = Utc::now();
        Self {
            id: pending.id,
            user_id: pending.user_id,
            name: pending.name,
            device_type: pending.device_type,
            ecdh_public_key: pending.ecdh_public_key,
            signing_public_key: pending.signing_public_key,
            identity_signature,
            client_nonce: pending.client_nonce,
            last_seen_at: now,
            created_at: now,
            revoked_at: None,
        }
    }

    /// Create a new device (for initial device during account creation)
    pub fn new(
        user_id: UserId,
        name: String,
        device_type: DeviceType,
        public_keys: PublicKeyPair,
        identity_signature: Vec<u8>,
        client_nonce: Vec<u8>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: DeviceId::new(),
            user_id,
            name,
            device_type,
            ecdh_public_key: public_keys.ecdh_public_key,
            signing_public_key: public_keys.signing_public_key,
            identity_signature,
            client_nonce,
            last_seen_at: now,
            created_at: now,
            revoked_at: None,
        }
    }

    /// Check if device is revoked
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Revoke the device
    pub fn revoke(&mut self) {
        self.revoked_at = Some(Utc::now());
    }

}

/// Pending device awaiting SAS verification
#[derive(Debug, Clone)]
pub struct PendingDevice {
    pub id: DeviceId,
    pub user_id: UserId,
    pub name: String,
    pub device_type: DeviceType,
    /// X25519 ECDH public key (32 bytes)
    pub ecdh_public_key: Vec<u8>,
    /// Ed25519 signing public key (32 bytes)
    pub signing_public_key: Vec<u8>,
    /// Client nonce for SAS verification (16 bytes)
    pub client_nonce: Vec<u8>,
    /// IP address of the requesting device
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Expires after ~5 minutes
    pub expires_at: DateTime<Utc>,
}

impl PendingDevice {
    /// Default expiration time in seconds
    const DEFAULT_EXPIRATION_SECS: i64 = 300; // 5 minutes

    pub fn new(
        user_id: UserId,
        name: String,
        device_type: DeviceType,
        public_keys: PublicKeyPair,
        client_nonce: Vec<u8>,
        ip_address: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: DeviceId::new(),
            user_id,
            name,
            device_type,
            ecdh_public_key: public_keys.ecdh_public_key,
            signing_public_key: public_keys.signing_public_key,
            client_nonce,
            ip_address,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(Self::DEFAULT_EXPIRATION_SECS),
        }
    }

    /// Check if the pending device has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}
