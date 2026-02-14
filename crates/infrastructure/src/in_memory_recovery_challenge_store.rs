//! In-memory recovery challenge store for single-node deployments

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use domain::recovery_challenge::{RecoveryChallengeError, RecoveryChallengeStore};

use crate::in_memory_nonce_map::{FromNonceMapError, InMemoryNonceMap};
use crate::in_memory_ttl_store::TtlCleanup;

/// In-memory recovery challenge store for single-node deployments
///
/// Stores (email, challenge) -> expires_at mappings.
/// Each challenge can only be used once (removed on verification).
pub struct InMemoryRecoveryChallengeStore {
    map: InMemoryNonceMap<(String, [u8; 32])>,
}

impl InMemoryRecoveryChallengeStore {
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            map: InMemoryNonceMap::new(TtlCleanup::new(cleanup_interval)),
        }
    }
}

impl Default for InMemoryRecoveryChallengeStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

impl_from_nonce_map_error!(RecoveryChallengeError);

#[async_trait]
impl RecoveryChallengeStore for InMemoryRecoveryChallengeStore {
    async fn store(
        &self,
        email: &str,
        challenge: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), RecoveryChallengeError> {
        self.map
            .store((email.to_lowercase(), challenge), expires_at)
            .map_err(RecoveryChallengeError::from_nonce_map_error)
    }

    async fn verify(
        &self,
        email: &str,
        challenge: &[u8; 32],
    ) -> Result<(), RecoveryChallengeError> {
        self.map
            .verify(&(email.to_lowercase(), *challenge))
            .map_err(RecoveryChallengeError::from_nonce_map_error)
    }

    async fn consume(
        &self,
        email: &str,
        challenge: &[u8; 32],
    ) -> Result<(), RecoveryChallengeError> {
        self.map
            .consume(&(email.to_lowercase(), *challenge))
            .map_err(RecoveryChallengeError::from_nonce_map_error)
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

        store.store(email, challenge, expires_at).await.unwrap();
        assert!(store.verify(email, &challenge).await.is_ok());
        assert!(store.consume(email, &challenge).await.is_ok());
        assert_eq!(
            store.verify(email, &challenge).await,
            Err(RecoveryChallengeError::NotFound)
        );
    }

    #[tokio::test]
    async fn test_recovery_challenge_store_expired() {
        let store = InMemoryRecoveryChallengeStore::new(Duration::from_secs(60));
        let email = "test@example.com";
        let challenge = [2u8; 32];
        let expires_at = Utc::now() - ChronoDuration::seconds(1);

        store.store(email, challenge, expires_at).await.unwrap();
        assert_eq!(
            store.verify(email, &challenge).await,
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

        store.store(email_lower, challenge, expires_at).await.unwrap();
        assert!(store.verify(email_upper, &challenge).await.is_ok());
        assert!(store.consume(email_upper, &challenge).await.is_ok());
    }

    #[tokio::test]
    async fn test_recovery_challenge_store_wrong_email() {
        let store = InMemoryRecoveryChallengeStore::new(Duration::from_secs(60));
        let email1 = "user1@example.com";
        let email2 = "user2@example.com";
        let challenge = [4u8; 32];
        let expires_at = Utc::now() + ChronoDuration::minutes(5);

        store.store(email1, challenge, expires_at).await.unwrap();
        assert_eq!(
            store.verify(email2, &challenge).await,
            Err(RecoveryChallengeError::NotFound)
        );
        assert!(store.verify(email1, &challenge).await.is_ok());
        assert!(store.consume(email1, &challenge).await.is_ok());
    }
}
