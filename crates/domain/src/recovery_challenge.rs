//! Recovery Challenge types for recovery session authentication
//!
//! Defines the RecoveryChallengeStore trait for storing and verifying
//! recovery challenges used in the password-free recovery flow.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Recovery challenge verification error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryChallengeError {
    /// Challenge not found (invalid or already used)
    NotFound,
    /// Challenge has expired
    Expired,
    /// Store operation failed (e.g., Redis connection error)
    StoreError,
}

impl std::fmt::Display for RecoveryChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryChallengeError::NotFound => write!(f, "challenge not found or already used"),
            RecoveryChallengeError::Expired => write!(f, "challenge has expired"),
            RecoveryChallengeError::StoreError => write!(f, "challenge store error"),
        }
    }
}

impl std::error::Error for RecoveryChallengeError {}

/// Trait for recovery challenge storage backends
///
/// Recovery challenges are keyed by email address (unlike PoP challenges
/// which are keyed by DeviceId). This is because recovery happens before
/// the user has an authenticated session or device.
///
/// Supports both in-memory (single-node) and Redis (cluster) implementations.
#[async_trait]
pub trait RecoveryChallengeStore: Send + Sync {
    /// Store a new challenge for an email
    ///
    /// Returns error if storage fails (e.g., Redis connection error).
    /// For user enumeration prevention, always returns success even for
    /// non-existent users (the challenge just won't be usable).
    async fn store(
        &self,
        email: &str,
        challenge: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), RecoveryChallengeError>;

    /// Verify challenge exists and is valid (does NOT consume)
    ///
    /// Use this to check challenge validity before performing expensive
    /// operations like signature verification. Call `consume` after
    /// all validations pass.
    async fn verify(
        &self,
        email: &str,
        challenge: &[u8; 32],
    ) -> Result<(), RecoveryChallengeError>;

    /// Consume (remove) a previously verified challenge
    ///
    /// Should only be called after `verify` succeeds and all other
    /// validations (signature, etc.) have passed.
    async fn consume(
        &self,
        email: &str,
        challenge: &[u8; 32],
    ) -> Result<(), RecoveryChallengeError>;
}
