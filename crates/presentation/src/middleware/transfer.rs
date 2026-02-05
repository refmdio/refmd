//! In-memory implementations of trust transfer stores for single-node deployments
//!
//! These implementations use RwLock-protected HashMaps for storing transfer nonces
//! and encrypted trust state. For cluster deployments, use Redis-backed implementations.

use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use application::domain::encryption::DeviceId;
use application::domain::identity::UserId;
use application::domain::transfer_nonce::{
    EncryptedTransferState, TransferNonceError, TransferNonceStore, TransferStateError,
    TransferStateStore,
};

// =============================================================================
// In-Memory Transfer Nonce Store
// =============================================================================

/// In-memory transfer nonce store for single-node deployments
///
/// Stores (user_id, device_id, nonce) → expires_at mappings.
/// Each nonce can only be used once (removed on verification).
pub struct InMemoryTransferNonceStore {
    /// (user_id, device_id, nonce) → expires_at
    nonces: RwLock<HashMap<(Uuid, Uuid, [u8; 32]), DateTime<Utc>>>,
    /// Cleanup interval
    cleanup_interval: Duration,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
}

impl InMemoryTransferNonceStore {
    /// Create a new transfer nonce store with specified cleanup interval
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            nonces: RwLock::new(HashMap::new()),
            cleanup_interval,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Periodic cleanup of expired nonces
    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let last = self.last_cleanup.read().unwrap();
            now.duration_since(*last) > self.cleanup_interval
        };

        if should_cleanup {
            let mut nonces = self.nonces.write().unwrap();
            let mut last = self.last_cleanup.write().unwrap();

            let now_utc = Utc::now();
            nonces.retain(|_, expires_at| *expires_at > now_utc);
            *last = now;
        }
    }
}

impl Default for InMemoryTransferNonceStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(60)) // Cleanup every minute
    }
}

#[async_trait]
impl TransferNonceStore for InMemoryTransferNonceStore {
    async fn store(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        nonce: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), TransferNonceError> {
        self.maybe_cleanup();

        let mut nonces = self.nonces.write().unwrap();
        nonces.insert(
            (user_id.as_uuid(), new_device_id.as_uuid(), nonce),
            expires_at,
        );
        Ok(())
    }

    async fn verify_and_consume(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        nonce: &[u8; 32],
    ) -> Result<(), TransferNonceError> {
        self.maybe_cleanup();

        let mut nonces = self.nonces.write().unwrap();
        let key = (user_id.as_uuid(), new_device_id.as_uuid(), *nonce);

        match nonces.remove(&key) {
            Some(expires_at) => {
                if expires_at < Utc::now() {
                    Err(TransferNonceError::Expired)
                } else {
                    Ok(())
                }
            }
            None => Err(TransferNonceError::NotFound),
        }
    }
}

// =============================================================================
// In-Memory Transfer State Store
// =============================================================================

/// Stored transfer state with expiration
struct StoredTransferState {
    state: EncryptedTransferState,
    expires_at: DateTime<Utc>,
}

/// In-memory transfer state store for single-node deployments
///
/// Stores encrypted trust state temporarily for new devices to retrieve.
pub struct InMemoryTransferStateStore {
    /// (user_id, device_id) → StoredTransferState
    states: RwLock<HashMap<(Uuid, Uuid), StoredTransferState>>,
    /// Cleanup interval
    cleanup_interval: Duration,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
}

impl InMemoryTransferStateStore {
    /// Create a new transfer state store with specified cleanup interval
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
            cleanup_interval,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Periodic cleanup of expired states
    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let last = self.last_cleanup.read().unwrap();
            now.duration_since(*last) > self.cleanup_interval
        };

        if should_cleanup {
            let mut states = self.states.write().unwrap();
            let mut last = self.last_cleanup.write().unwrap();

            let now_utc = Utc::now();
            states.retain(|_, stored| stored.expires_at > now_utc);
            *last = now;
        }
    }
}

impl Default for InMemoryTransferStateStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(60)) // Cleanup every minute
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

        let mut states = self.states.write().unwrap();
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

        let mut states = self.states.write().unwrap();
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
