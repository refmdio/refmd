//! Proof of Possession (PoP) domain types
//!
//! Defines the ChallengeStore trait and related types for PoP verification.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::encryption::DeviceId;

/// Challenge verification error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    /// Challenge not found (invalid or already used)
    NotFound,
    /// Challenge has expired
    Expired,
    /// Store operation failed (e.g., Redis connection error)
    StoreError,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallengeError::NotFound => write!(f, "challenge not found or already used"),
            ChallengeError::Expired => write!(f, "challenge has expired"),
            ChallengeError::StoreError => write!(f, "challenge store error"),
        }
    }
}

impl std::error::Error for ChallengeError {}

/// Trait for challenge storage backends
///
/// Supports both in-memory (single-node) and Redis (cluster) implementations.
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Store a new challenge for a device
    /// Returns error if storage fails (e.g., Redis connection error)
    async fn store(
        &self,
        device_id: DeviceId,
        challenge: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), ChallengeError>;

    /// Verify challenge exists and is valid (does NOT consume)
    async fn verify(&self, device_id: DeviceId, challenge: &[u8; 32])
    -> Result<(), ChallengeError>;

    /// Consume (remove) a previously verified challenge
    async fn consume(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError>;

    /// Verify and consume a challenge atomically
    async fn verify_and_remove(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError>;
}
