//! In-memory transfer nonce and state stores for single-node deployments

use std::{collections::HashMap, sync::RwLock, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use domain::encryption::DeviceId;
use domain::identity::UserId;
use domain::transfer_nonce::{
    EncryptedTransferState, TransferNonceError, TransferNonceStore, TransferStateError,
    TransferStateStore,
};

use crate::in_memory_nonce_map::{FromNonceMapError, InMemoryNonceMap};
use crate::in_memory_ttl_store::TtlCleanup;

// =============================================================================
// In-Memory Transfer Nonce Store
// =============================================================================

/// In-memory transfer nonce store for single-node deployments
///
/// Stores (user_id, device_id, nonce) -> expires_at mappings.
/// Each nonce can only be used once (removed on verification).
pub struct InMemoryTransferNonceStore {
    map: InMemoryNonceMap<(Uuid, Uuid, [u8; 32])>,
}

impl InMemoryTransferNonceStore {
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            map: InMemoryNonceMap::new(TtlCleanup::new(cleanup_interval)),
        }
    }
}

impl Default for InMemoryTransferNonceStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

impl_from_nonce_map_error!(TransferNonceError);

#[async_trait]
impl TransferNonceStore for InMemoryTransferNonceStore {
    async fn store(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        nonce: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), TransferNonceError> {
        self.map
            .store(
                (user_id.as_uuid(), new_device_id.as_uuid(), nonce),
                expires_at,
            )
            .map_err(TransferNonceError::from_nonce_map_error)
    }

    async fn verify_and_consume(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        nonce: &[u8; 32],
    ) -> Result<(), TransferNonceError> {
        self.map
            .verify_and_remove(&(user_id.as_uuid(), new_device_id.as_uuid(), *nonce))
            .map_err(TransferNonceError::from_nonce_map_error)
    }
}

// =============================================================================
// In-Memory Transfer State Store
// =============================================================================

struct StoredTransferState {
    state: EncryptedTransferState,
    expires_at: DateTime<Utc>,
}

/// In-memory transfer state store for single-node deployments
///
/// Stores encrypted trust state temporarily for new devices to retrieve.
pub struct InMemoryTransferStateStore {
    states: RwLock<HashMap<(Uuid, Uuid), StoredTransferState>>,
    ttl: TtlCleanup,
}

impl InMemoryTransferStateStore {
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
            ttl: TtlCleanup::new(cleanup_interval),
        }
    }

    fn maybe_cleanup(&self) {
        let states = &self.states;
        self.ttl.maybe_cleanup(|| {
            let mut map = states.write().unwrap_or_else(|e| e.into_inner());
            let now = Utc::now();
            map.retain(|_, stored| stored.expires_at > now);
        });
    }
}

impl Default for InMemoryTransferStateStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

#[async_trait]
impl TransferStateStore for InMemoryTransferStateStore {
    async fn store(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        state: EncryptedTransferState,
        expires_at: DateTime<Utc>,
    ) -> Result<(), TransferStateError> {
        self.maybe_cleanup();
        let mut states = self.states.write().map_err(|_| TransferStateError::StoreError)?;
        states.insert(
            (user_id.as_uuid(), new_device_id.as_uuid()),
            StoredTransferState { state, expires_at },
        );
        Ok(())
    }

    async fn retrieve_and_consume(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
    ) -> Result<EncryptedTransferState, TransferStateError> {
        self.maybe_cleanup();
        let mut states = self.states.write().map_err(|_| TransferStateError::StoreError)?;
        let key = (user_id.as_uuid(), new_device_id.as_uuid());
        match states.remove(&key) {
            Some(stored) => {
                if stored.expires_at < Utc::now() {
                    Err(TransferStateError::NotFound)
                } else {
                    Ok(stored.state)
                }
            }
            None => Err(TransferStateError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    fn test_user() -> UserId {
        UserId::from_uuid(Uuid::new_v4())
    }

    fn test_device() -> DeviceId {
        DeviceId::from_uuid(Uuid::new_v4())
    }

    fn test_state() -> EncryptedTransferState {
        EncryptedTransferState {
            ciphertext: vec![1, 2, 3, 4],
            nonce: [0u8; 24],
            signature: [0u8; 64],
            sender_device_id: test_device(),
        }
    }

    // =========================================================================
    // TransferNonceStore tests
    // =========================================================================

    #[tokio::test]
    async fn nonce_store_and_consume() {
        let store = InMemoryTransferNonceStore::default();
        let user = test_user();
        let device = test_device();
        let nonce = [1u8; 32];
        let expires = Utc::now() + ChronoDuration::minutes(5);

        store.store(user, device, nonce, expires).await.unwrap();
        store.verify_and_consume(user, device, &nonce).await.unwrap();
    }

    #[tokio::test]
    async fn nonce_consumed_cannot_reuse() {
        let store = InMemoryTransferNonceStore::default();
        let user = test_user();
        let device = test_device();
        let nonce = [2u8; 32];
        let expires = Utc::now() + ChronoDuration::minutes(5);

        store.store(user, device, nonce, expires).await.unwrap();
        store.verify_and_consume(user, device, &nonce).await.unwrap();
        assert_eq!(
            store.verify_and_consume(user, device, &nonce).await,
            Err(TransferNonceError::NotFound),
        );
    }

    #[tokio::test]
    async fn nonce_expired() {
        let store = InMemoryTransferNonceStore::default();
        let user = test_user();
        let device = test_device();
        let nonce = [3u8; 32];
        let expires = Utc::now() - ChronoDuration::seconds(1);

        store.store(user, device, nonce, expires).await.unwrap();
        assert_eq!(
            store.verify_and_consume(user, device, &nonce).await,
            Err(TransferNonceError::Expired),
        );
    }

    #[tokio::test]
    async fn nonce_wrong_device() {
        let store = InMemoryTransferNonceStore::default();
        let user = test_user();
        let device1 = test_device();
        let device2 = test_device();
        let nonce = [4u8; 32];
        let expires = Utc::now() + ChronoDuration::minutes(5);

        store.store(user, device1, nonce, expires).await.unwrap();
        assert_eq!(
            store.verify_and_consume(user, device2, &nonce).await,
            Err(TransferNonceError::NotFound),
        );
    }

    #[tokio::test]
    async fn nonce_wrong_user() {
        let store = InMemoryTransferNonceStore::default();
        let user1 = test_user();
        let user2 = test_user();
        let device = test_device();
        let nonce = [5u8; 32];
        let expires = Utc::now() + ChronoDuration::minutes(5);

        store.store(user1, device, nonce, expires).await.unwrap();
        assert_eq!(
            store.verify_and_consume(user2, device, &nonce).await,
            Err(TransferNonceError::NotFound),
        );
    }

    // =========================================================================
    // TransferStateStore tests
    // =========================================================================

    #[tokio::test]
    async fn state_store_and_retrieve() {
        let store = InMemoryTransferStateStore::default();
        let user = test_user();
        let device = test_device();
        let state = test_state();
        let expires = Utc::now() + ChronoDuration::minutes(5);

        store.store(user, device, state.clone(), expires).await.unwrap();
        let retrieved = store.retrieve_and_consume(user, device).await.unwrap();
        assert_eq!(retrieved.ciphertext, state.ciphertext);
    }

    #[tokio::test]
    async fn state_consumed_cannot_retrieve_again() {
        let store = InMemoryTransferStateStore::default();
        let user = test_user();
        let device = test_device();
        let expires = Utc::now() + ChronoDuration::minutes(5);

        store.store(user, device, test_state(), expires).await.unwrap();
        store.retrieve_and_consume(user, device).await.unwrap();
        assert!(
            matches!(store.retrieve_and_consume(user, device).await, Err(TransferStateError::NotFound)),
        );
    }

    #[tokio::test]
    async fn state_expired() {
        let store = InMemoryTransferStateStore::default();
        let user = test_user();
        let device = test_device();
        let expires = Utc::now() - ChronoDuration::seconds(1);

        store.store(user, device, test_state(), expires).await.unwrap();
        assert!(
            matches!(store.retrieve_and_consume(user, device).await, Err(TransferStateError::NotFound)),
        );
    }

    #[tokio::test]
    async fn state_wrong_device() {
        let store = InMemoryTransferStateStore::default();
        let user = test_user();
        let device1 = test_device();
        let device2 = test_device();
        let expires = Utc::now() + ChronoDuration::minutes(5);

        store.store(user, device1, test_state(), expires).await.unwrap();
        assert!(
            matches!(store.retrieve_and_consume(user, device2).await, Err(TransferStateError::NotFound)),
        );
    }

    #[tokio::test]
    async fn state_overwrite() {
        let store = InMemoryTransferStateStore::default();
        let user = test_user();
        let device = test_device();
        let expires = Utc::now() + ChronoDuration::minutes(5);

        let state1 = EncryptedTransferState {
            ciphertext: vec![1, 1, 1],
            ..test_state()
        };
        let state2 = EncryptedTransferState {
            ciphertext: vec![2, 2, 2],
            ..test_state()
        };

        store.store(user, device, state1, expires).await.unwrap();
        store.store(user, device, state2.clone(), expires).await.unwrap();
        let retrieved = store.retrieve_and_consume(user, device).await.unwrap();
        assert_eq!(retrieved.ciphertext, state2.ciphertext);
    }
}
