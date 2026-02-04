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

use chrono::{DateTime, Utc};
use uuid::Uuid;

use application::domain::encryption::DeviceId;

/// PoP header names
pub const POP_CHALLENGE_HEADER: &str = "X-PoP-Challenge";
pub const POP_SIGNATURE_HEADER: &str = "X-PoP-Signature";
pub const POP_DEVICE_ID_HEADER: &str = "X-PoP-Device-Id";

/// Challenge TTL (5 minutes)
pub const CHALLENGE_TTL_SECS: i64 = 300;

/// Challenge cache for server-issued PoP challenges
///
/// Stores (device_id, challenge) → expires_at mappings.
/// Each challenge can only be used once (removed on verification).
pub struct ChallengeCache {
    /// (device_id, challenge_bytes) → expires_at
    challenges: RwLock<HashMap<(Uuid, [u8; 32]), DateTime<Utc>>>,
    /// Cleanup interval
    cleanup_interval: Duration,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
}

impl ChallengeCache {
    /// Create a new challenge cache
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            challenges: RwLock::new(HashMap::new()),
            cleanup_interval,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Store a new challenge for a device
    ///
    /// Returns the challenge bytes for sending to client.
    pub fn store(&self, device_id: DeviceId, challenge: [u8; 32], expires_at: DateTime<Utc>) {
        self.maybe_cleanup();

        let mut challenges = self.challenges.write().unwrap();
        challenges.insert((device_id.as_uuid(), challenge), expires_at);
    }

    /// Verify and consume a challenge
    ///
    /// Returns Ok(()) if the challenge is valid and not expired.
    /// The challenge is removed after verification (one-time use).
    ///
    /// Note: Prefer using `verify()` followed by `consume()` separately
    /// when signature verification happens between them, to avoid consuming
    /// the challenge on invalid signature attempts.
    pub fn verify_and_remove(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        self.maybe_cleanup();

        let mut challenges = self.challenges.write().unwrap();
        let key = (device_id.as_uuid(), *challenge);

        // Remove and check in one operation
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

    /// Verify challenge exists and is valid (does NOT consume)
    ///
    /// Use this when you need to verify signature validity before consuming.
    /// Follow up with `consume()` after successful signature verification.
    pub fn verify(&self, device_id: DeviceId, challenge: &[u8; 32]) -> Result<(), ChallengeError> {
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

    /// Consume (remove) a previously verified challenge
    ///
    /// Call this after successful signature verification.
    /// Returns Ok(()) if successfully consumed, Err if already consumed (concurrent request).
    pub fn consume(&self, device_id: DeviceId, challenge: &[u8; 32]) -> Result<(), ChallengeError> {
        let mut challenges = self.challenges.write().unwrap();
        match challenges.remove(&(device_id.as_uuid(), *challenge)) {
            Some(_) => Ok(()),
            None => Err(ChallengeError::NotFound),
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

impl Default for ChallengeCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(60)) // Cleanup every minute
    }
}

/// Challenge verification error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    /// Challenge not found (invalid or already used)
    NotFound,
    /// Challenge has expired
    Expired,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallengeError::NotFound => write!(f, "challenge not found or already used"),
            ChallengeError::Expired => write!(f, "challenge has expired"),
        }
    }
}

impl std::error::Error for ChallengeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[test]
    fn test_challenge_cache_basic() {
        let cache = ChallengeCache::new(Duration::from_secs(60));
        let device_id = DeviceId::from_uuid(Uuid::new_v4());
        let challenge = [1u8; 32];
        let expires_at = Utc::now() + ChronoDuration::minutes(5);

        // Store challenge
        cache.store(device_id, challenge, expires_at);

        // First verification should succeed
        assert!(cache.verify_and_remove(device_id, &challenge).is_ok());

        // Second verification should fail (challenge consumed)
        assert_eq!(
            cache.verify_and_remove(device_id, &challenge),
            Err(ChallengeError::NotFound)
        );
    }

    #[test]
    fn test_challenge_cache_expired() {
        let cache = ChallengeCache::new(Duration::from_secs(60));
        let device_id = DeviceId::from_uuid(Uuid::new_v4());
        let challenge = [2u8; 32];
        let expires_at = Utc::now() - ChronoDuration::seconds(1); // Already expired

        cache.store(device_id, challenge, expires_at);

        // Verification should fail (expired)
        assert_eq!(
            cache.verify_and_remove(device_id, &challenge),
            Err(ChallengeError::Expired)
        );
    }

    #[test]
    fn test_challenge_cache_wrong_device() {
        let cache = ChallengeCache::new(Duration::from_secs(60));
        let device_id1 = DeviceId::from_uuid(Uuid::new_v4());
        let device_id2 = DeviceId::from_uuid(Uuid::new_v4());
        let challenge = [3u8; 32];
        let expires_at = Utc::now() + ChronoDuration::minutes(5);

        cache.store(device_id1, challenge, expires_at);

        // Verification with wrong device should fail
        assert_eq!(
            cache.verify_and_remove(device_id2, &challenge),
            Err(ChallengeError::NotFound)
        );

        // Verification with correct device should succeed
        assert!(cache.verify_and_remove(device_id1, &challenge).is_ok());
    }

    #[test]
    fn test_challenge_cache_verify_without_consume() {
        let cache = ChallengeCache::new(Duration::from_secs(60));
        let device_id = DeviceId::from_uuid(Uuid::new_v4());
        let challenge = [4u8; 32];
        let expires_at = Utc::now() + ChronoDuration::minutes(5);

        cache.store(device_id, challenge, expires_at);

        // Verify should succeed without consuming
        assert!(cache.verify(device_id, &challenge).is_ok());

        // Verify should still succeed (not consumed)
        assert!(cache.verify(device_id, &challenge).is_ok());

        // Now consume - should succeed
        assert!(cache.consume(device_id, &challenge).is_ok());

        // Verify should fail after consume
        assert_eq!(
            cache.verify(device_id, &challenge),
            Err(ChallengeError::NotFound)
        );

        // Second consume should fail (already consumed)
        assert_eq!(
            cache.consume(device_id, &challenge),
            Err(ChallengeError::NotFound)
        );
    }

    #[test]
    fn test_challenge_cache_verify_expired() {
        let cache = ChallengeCache::new(Duration::from_secs(60));
        let device_id = DeviceId::from_uuid(Uuid::new_v4());
        let challenge = [5u8; 32];
        let expires_at = Utc::now() - ChronoDuration::seconds(1); // Already expired

        cache.store(device_id, challenge, expires_at);

        // Verify should fail (expired)
        assert_eq!(
            cache.verify(device_id, &challenge),
            Err(ChallengeError::Expired)
        );
    }
}
