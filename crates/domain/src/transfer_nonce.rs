//! Trust State Transfer types
//!
//! Defines traits for trust state transfer operations:
//! - TransferNonceStore: Nonce management for replay protection
//! - TransferStateStore: Temporary storage for encrypted trust state

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::encryption::DeviceId;
use crate::identity::UserId;

/// Transfer nonce verification error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferNonceError {
    /// Nonce not found (invalid or already used)
    NotFound,
    /// Nonce has expired
    Expired,
    /// Store operation failed (e.g., Redis connection error)
    StoreError,
}

impl std::fmt::Display for TransferNonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferNonceError::NotFound => write!(f, "nonce not found or already used"),
            TransferNonceError::Expired => write!(f, "nonce has expired"),
            TransferNonceError::StoreError => write!(f, "transfer nonce store error"),
        }
    }
}

impl std::error::Error for TransferNonceError {}

/// Trait for transfer nonce storage backends
///
/// Transfer nonces are keyed by user_id + device_id (the new device requesting transfer).
/// Single-use nonces with 5-minute TTL for replay protection.
///
/// Supports both in-memory (single-node) and Redis (cluster) implementations.
#[async_trait]
pub trait TransferNonceStore: Send + Sync {
    /// Store a new transfer nonce for a device
    ///
    /// The nonce is bound to a specific user and new device, preventing
    /// nonce reuse across different transfer sessions.
    ///
    /// Returns error if storage fails (e.g., Redis connection error).
    async fn store(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        nonce: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), TransferNonceError>;

    /// Verify and consume a transfer nonce atomically
    ///
    /// Returns Ok(()) if the nonce is valid and was successfully consumed.
    /// Returns Err(NotFound) if the nonce doesn't exist or was already used.
    /// Returns Err(Expired) if the nonce has expired.
    ///
    /// The nonce is consumed on successful verification to prevent replay attacks.
    async fn verify_and_consume(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        nonce: &[u8; 32],
    ) -> Result<(), TransferNonceError>;
}

/// Transfer state storage error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStateError {
    /// State not found (not yet submitted or expired)
    NotFound,
    /// Store operation failed (e.g., Redis connection error)
    StoreError,
}

impl std::fmt::Display for TransferStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferStateError::NotFound => write!(f, "transfer state not found"),
            TransferStateError::StoreError => write!(f, "transfer state store error"),
        }
    }
}

impl std::error::Error for TransferStateError {}

/// Encrypted trust state data
#[derive(Debug, Clone)]
pub struct EncryptedTransferState {
    /// XChaCha20-Poly1305 ciphertext
    pub ciphertext: Vec<u8>,
    /// XChaCha20-Poly1305 nonce (24 bytes)
    pub nonce: [u8; 24],
    /// Ed25519 signature over ciphertext + transfer_nonce
    pub signature: [u8; 64],
    /// Device ID of the sender (existing device)
    pub sender_device_id: DeviceId,
}

/// Trait for temporary storage of encrypted trust state
///
/// The encrypted trust state is stored briefly while the new device
/// retrieves it. Uses a 5-minute TTL for security.
///
/// Key: user_id + new_device_id
/// Value: EncryptedTransferState
#[async_trait]
pub trait TransferStateStore: Send + Sync {
    /// Store encrypted trust state for a new device
    ///
    /// Overwrites any existing state for this user+device combination.
    /// The state expires after TTL (typically 5 minutes).
    async fn store(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        state: EncryptedTransferState,
        expires_at: DateTime<Utc>,
    ) -> Result<(), TransferStateError>;

    /// Retrieve and consume encrypted trust state
    ///
    /// Returns the stored state and removes it atomically.
    /// Returns Err(NotFound) if no state exists or it has expired.
    async fn retrieve_and_consume(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
    ) -> Result<EncryptedTransferState, TransferStateError>;
}
