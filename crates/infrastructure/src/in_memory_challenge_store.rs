//! In-memory PoP challenge store for single-node deployments

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use domain::encryption::DeviceId;
use domain::pop::{ChallengeError, ChallengeStore};

use crate::in_memory_nonce_map::{FromNonceMapError, InMemoryNonceMap};
use crate::in_memory_ttl_store::TtlCleanup;

/// In-memory challenge cache for single-node deployments
///
/// Stores (device_id, challenge) -> expires_at mappings.
/// Each challenge can only be used once (removed on verification).
pub struct InMemoryChallengeStore {
    map: InMemoryNonceMap<(Uuid, [u8; 32])>,
}

impl InMemoryChallengeStore {
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            map: InMemoryNonceMap::new(TtlCleanup::new(cleanup_interval)),
        }
    }
}

impl Default for InMemoryChallengeStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

impl_from_nonce_map_error!(ChallengeError);

#[async_trait]
impl ChallengeStore for InMemoryChallengeStore {
    async fn store(
        &self,
        device_id: DeviceId,
        challenge: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), ChallengeError> {
        self.map
            .store((device_id.as_uuid(), challenge), expires_at)
            .map_err(ChallengeError::from_nonce_map_error)
    }

    async fn verify(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        self.map
            .verify(&(device_id.as_uuid(), *challenge))
            .map_err(ChallengeError::from_nonce_map_error)
    }

    async fn consume(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        self.map
            .consume(&(device_id.as_uuid(), *challenge))
            .map_err(ChallengeError::from_nonce_map_error)
    }

    async fn verify_and_remove(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        self.map
            .verify_and_remove(&(device_id.as_uuid(), *challenge))
            .map_err(ChallengeError::from_nonce_map_error)
    }
}

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

        store.store(device_id, challenge, expires_at).await.unwrap();
        assert!(store.verify_and_remove(device_id, &challenge).await.is_ok());
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
        let expires_at = Utc::now() - ChronoDuration::seconds(1);

        store.store(device_id, challenge, expires_at).await.unwrap();
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
        assert_eq!(
            store.verify_and_remove(device_id2, &challenge).await,
            Err(ChallengeError::NotFound)
        );
        assert!(store.verify_and_remove(device_id1, &challenge).await.is_ok());
    }

    #[tokio::test]
    async fn test_challenge_store_verify_without_consume() {
        let store = InMemoryChallengeStore::new(Duration::from_secs(60));
        let device_id = DeviceId::from_uuid(Uuid::new_v4());
        let challenge = [4u8; 32];
        let expires_at = Utc::now() + ChronoDuration::minutes(5);

        store.store(device_id, challenge, expires_at).await.unwrap();
        assert!(store.verify(device_id, &challenge).await.is_ok());
        assert!(store.verify(device_id, &challenge).await.is_ok());
        assert!(store.consume(device_id, &challenge).await.is_ok());
        assert_eq!(
            store.verify(device_id, &challenge).await,
            Err(ChallengeError::NotFound)
        );
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
        let expires_at = Utc::now() - ChronoDuration::seconds(1);

        store.store(device_id, challenge, expires_at).await.unwrap();
        assert_eq!(
            store.verify(device_id, &challenge).await,
            Err(ChallengeError::Expired)
        );
    }
}
