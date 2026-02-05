//! Recovery Challenge store implementations
//!
//! In-memory implementation for single-node deployments.

use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

// Re-export from domain for convenience
pub use application::domain::recovery_challenge::{RecoveryChallengeError, RecoveryChallengeStore};

/// In-memory recovery challenge store for single-node deployments
///
/// Stores (email, challenge) → expires_at mappings.
/// Each challenge can only be used once (removed on verification).
pub struct InMemoryRecoveryChallengeStore {
    /// (email, challenge_bytes) → expires_at
    challenges: RwLock<HashMap<(String, [u8; 32]), DateTime<Utc>>>,
    /// Cleanup interval
    cleanup_interval: Duration,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
}

impl InMemoryRecoveryChallengeStore {
    /// Create a new recovery challenge store with specified cleanup interval
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

impl Default for InMemoryRecoveryChallengeStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(60)) // Cleanup every minute
    }
}

#[async_trait]
impl RecoveryChallengeStore for InMemoryRecoveryChallengeStore {
    async fn store(
        &self,
        email: &str,
        challenge: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), RecoveryChallengeError> {
        self.maybe_cleanup();

        let mut challenges = self.challenges.write().unwrap();
        challenges.insert((email.to_lowercase(), challenge), expires_at);
        Ok(())
    }

    async fn verify(
        &self,
        email: &str,
        challenge: &[u8; 32],
    ) -> Result<(), RecoveryChallengeError> {
        self.maybe_cleanup();

        let challenges = self.challenges.read().unwrap();
        let key = (email.to_lowercase(), *challenge);

        match challenges.get(&key) {
            Some(expires_at) => {
                if *expires_at < Utc::now() {
                    Err(RecoveryChallengeError::Expired)
                } else {
                    Ok(())
                }
            }
            None => Err(RecoveryChallengeError::NotFound),
        }
    }

    async fn consume(
        &self,
        email: &str,
        challenge: &[u8; 32],
    ) -> Result<(), RecoveryChallengeError> {
        let mut challenges = self.challenges.write().unwrap();
        match challenges.remove(&(email.to_lowercase(), *challenge)) {
            Some(_) => Ok(()),
            None => Err(RecoveryChallengeError::NotFound),
        }
    }

    async fn verify_and_remove(
        &self,
        email: &str,
        challenge: &[u8; 32],
    ) -> Result<(), RecoveryChallengeError> {
        self.maybe_cleanup();

        let mut challenges = self.challenges.write().unwrap();
        let key = (email.to_lowercase(), *challenge);

        match challenges.remove(&key) {
            Some(expires_at) => {
                if expires_at < Utc::now() {
                    Err(RecoveryChallengeError::Expired)
                } else {
                    Ok(())
                }
            }
            None => Err(RecoveryChallengeError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[tokio::test]
    async fn test_recovery_challenge_store_basic() {
        let store = InMemoryRecoveryChallengeStore::new(Duration::from_secs(60));
        let email = "test@example.com";
        let challenge = [1u8; 32];
        let expires_at = Utc::now() + ChronoDuration::minutes(5);

        // Store challenge
        store.store(email, challenge, expires_at).await.unwrap();

        // First verification should succeed
        assert!(store.verify_and_remove(email, &challenge).await.is_ok());

        // Second verification should fail (challenge consumed)
        assert_eq!(
            store.verify_and_remove(email, &challenge).await,
            Err(RecoveryChallengeError::NotFound)
        );
    }

    #[tokio::test]
    async fn test_recovery_challenge_store_expired() {
        let store = InMemoryRecoveryChallengeStore::new(Duration::from_secs(60));
        let email = "test@example.com";
        let challenge = [2u8; 32];
        let expires_at = Utc::now() - ChronoDuration::seconds(1); // Already expired

        store.store(email, challenge, expires_at).await.unwrap();

        // Verification should fail (expired)
        assert_eq!(
            store.verify_and_remove(email, &challenge).await,
            Err(RecoveryChallengeError::Expired)
        );
    }

    #[tokio::test]
    async fn test_recovery_challenge_store_case_insensitive() {
        let store = InMemoryRecoveryChallengeStore::new(Duration::from_secs(60));
        let email_lower = "test@example.com";
        let email_upper = "TEST@EXAMPLE.COM";
        let challenge = [3u8; 32];
        let expires_at = Utc::now() + ChronoDuration::minutes(5);

        // Store with lowercase
        store
            .store(email_lower, challenge, expires_at)
            .await
            .unwrap();

        // Verification with uppercase should succeed (email is case-insensitive)
        assert!(store.verify_and_remove(email_upper, &challenge).await.is_ok());
    }

    #[tokio::test]
    async fn test_recovery_challenge_store_wrong_email() {
        let store = InMemoryRecoveryChallengeStore::new(Duration::from_secs(60));
        let email1 = "user1@example.com";
        let email2 = "user2@example.com";
        let challenge = [4u8; 32];
        let expires_at = Utc::now() + ChronoDuration::minutes(5);

        store.store(email1, challenge, expires_at).await.unwrap();

        // Verification with wrong email should fail
        assert_eq!(
            store.verify_and_remove(email2, &challenge).await,
            Err(RecoveryChallengeError::NotFound)
        );

        // Verification with correct email should succeed
        assert!(store.verify_and_remove(email1, &challenge).await.is_ok());
    }
}
