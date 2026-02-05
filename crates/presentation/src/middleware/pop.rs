//! Proof of Possession (PoP) verification middleware
//!
//! ADR-009 compliant: Verifies device ownership via server-issued challenge.
//!
//! Headers required:
//! - X-PoP-Challenge: Server-issued 32 bytes base64url encoded challenge
//! - X-PoP-Signature: Ed25519 signature of challenge by device signing key
//! - X-PoP-Device-Id: Device UUID

use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use application::domain::encryption::DeviceId;

// Re-export from domain for backwards compatibility
pub use application::domain::pop::{ChallengeError, ChallengeStore};

/// PoP header names
pub const POP_CHALLENGE_HEADER: &str = "X-PoP-Challenge";
pub const POP_SIGNATURE_HEADER: &str = "X-PoP-Signature";
pub const POP_DEVICE_ID_HEADER: &str = "X-PoP-Device-Id";

/// Challenge TTL (5 minutes)
pub const CHALLENGE_TTL_SECS: i64 = 300;

// =============================================================================
// In-Memory Implementation (Single-Node)
// =============================================================================

/// In-memory challenge cache for single-node deployments
///
/// Stores (device_id, challenge) → expires_at mappings.
/// Each challenge can only be used once (removed on verification).
pub struct InMemoryChallengeStore {
    /// (device_id, challenge_bytes) → expires_at
    challenges: RwLock<HashMap<(Uuid, [u8; 32]), DateTime<Utc>>>,
    /// Cleanup interval
    cleanup_interval: Duration,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
}

impl InMemoryChallengeStore {
    /// Create a new challenge store with specified cleanup interval
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            challenges: RwLock::new(HashMap::new()),
            cleanup_interval,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Periodic cleanup of expired challenges
    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let last = self.last_cleanup.read().unwrap();
            now.duration_since(*last) > self.cleanup_interval
        };

        if should_cleanup {
            let mut challenges = self.challenges.write().unwrap();
            let mut last = self.last_cleanup.write().unwrap();

            let now_utc = Utc::now();
            challenges.retain(|_, expires_at| *expires_at > now_utc);
            *last = now;
        }
    }
}

impl Default for InMemoryChallengeStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(60)) // Cleanup every minute
    }
}

#[async_trait]
impl ChallengeStore for InMemoryChallengeStore {
    async fn store(
        &self,
        device_id: DeviceId,
        challenge: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), ChallengeError> {
        self.maybe_cleanup();

        let mut challenges = self.challenges.write().unwrap();
        challenges.insert((device_id.as_uuid(), challenge), expires_at);
        Ok(())
    }

    async fn verify(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        self.maybe_cleanup();

        let challenges = self.challenges.read().unwrap();
        let key = (device_id.as_uuid(), *challenge);

        match challenges.get(&key) {
            Some(expires_at) => {
                if *expires_at < Utc::now() {
                    Err(ChallengeError::Expired)
                } else {
                    Ok(())
                }
            }
            None => Err(ChallengeError::NotFound),
        }
    }

    async fn consume(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        let mut challenges = self.challenges.write().unwrap();
        match challenges.remove(&(device_id.as_uuid(), *challenge)) {
            Some(_) => Ok(()),
            None => Err(ChallengeError::NotFound),
        }
    }

    async fn verify_and_remove(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        self.maybe_cleanup();

        let mut challenges = self.challenges.write().unwrap();
        let key = (device_id.as_uuid(), *challenge);

        match challenges.remove(&key) {
            Some(expires_at) => {
                if expires_at < Utc::now() {
                    Err(ChallengeError::Expired)
                } else {
                    Ok(())
                }
            }
            None => Err(ChallengeError::NotFound),
        }
    }
}

// =============================================================================
// Legacy type alias for backward compatibility
// =============================================================================

/// Legacy alias - use InMemoryChallengeStore directly
pub type ChallengeCache = InMemoryChallengeStore;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[tokio::test]
    async fn test_challenge_store_basic() {
        let store = InMemoryChallengeStore::new(Duration::from_secs(60));
        let device_id = DeviceId::from_uuid(Uuid::new_v4());
        let challenge = [1u8; 32];
        let expires_at = Utc::now() + ChronoDuration::minutes(5);

        // Store challenge
        store.store(device_id, challenge, expires_at).await.unwrap();

        // First verification should succeed
        assert!(store.verify_and_remove(device_id, &challenge).await.is_ok());

        // Second verification should fail (challenge consumed)
        assert_eq!(
            store.verify_and_remove(device_id, &challenge).await,
            Err(ChallengeError::NotFound)
        );
    }

    #[tokio::test]
    async fn test_challenge_store_expired() {
        let store = InMemoryChallengeStore::new(Duration::from_secs(60));
        let device_id = DeviceId::from_uuid(Uuid::new_v4());
        let challenge = [2u8; 32];
        let expires_at = Utc::now() - ChronoDuration::seconds(1); // Already expired

        store.store(device_id, challenge, expires_at).await.unwrap();

        // Verification should fail (expired)
        assert_eq!(
            store.verify_and_remove(device_id, &challenge).await,
            Err(ChallengeError::Expired)
        );
    }

    #[tokio::test]
    async fn test_challenge_store_wrong_device() {
        let store = InMemoryChallengeStore::new(Duration::from_secs(60));
        let device_id1 = DeviceId::from_uuid(Uuid::new_v4());
        let device_id2 = DeviceId::from_uuid(Uuid::new_v4());
        let challenge = [3u8; 32];
        let expires_at = Utc::now() + ChronoDuration::minutes(5);

        store.store(device_id1, challenge, expires_at).await.unwrap();

        // Verification with wrong device should fail
        assert_eq!(
            store.verify_and_remove(device_id2, &challenge).await,
            Err(ChallengeError::NotFound)
        );

        // Verification with correct device should succeed
        assert!(
            store
                .verify_and_remove(device_id1, &challenge)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_challenge_store_verify_without_consume() {
        let store = InMemoryChallengeStore::new(Duration::from_secs(60));
        let device_id = DeviceId::from_uuid(Uuid::new_v4());
        let challenge = [4u8; 32];
        let expires_at = Utc::now() + ChronoDuration::minutes(5);

        store.store(device_id, challenge, expires_at).await.unwrap();

        // Verify should succeed without consuming
        assert!(store.verify(device_id, &challenge).await.is_ok());

        // Verify should still succeed (not consumed)
        assert!(store.verify(device_id, &challenge).await.is_ok());

        // Now consume - should succeed
        assert!(store.consume(device_id, &challenge).await.is_ok());

        // Verify should fail after consume
        assert_eq!(
            store.verify(device_id, &challenge).await,
            Err(ChallengeError::NotFound)
        );

        // Second consume should fail (already consumed)
        assert_eq!(
            store.consume(device_id, &challenge).await,
            Err(ChallengeError::NotFound)
        );
    }

    #[tokio::test]
    async fn test_challenge_store_verify_expired() {
        let store = InMemoryChallengeStore::new(Duration::from_secs(60));
        let device_id = DeviceId::from_uuid(Uuid::new_v4());
        let challenge = [5u8; 32];
        let expires_at = Utc::now() - ChronoDuration::seconds(1); // Already expired

        store.store(device_id, challenge, expires_at).await.unwrap();

        // Verify should fail (expired)
        assert_eq!(
            store.verify(device_id, &challenge).await,
            Err(ChallengeError::Expired)
        );
    }
}
