//! Generic in-memory nonce map shared by challenge stores
//!
//! Encapsulates the common (key → expires_at) pattern with RwLock-safe operations.

use std::{collections::HashMap, hash::Hash, sync::RwLock};

use chrono::{DateTime, Utc};

use crate::in_memory_ttl_store::TtlCleanup;

/// Error from nonce map operations
#[derive(Debug)]
pub(crate) enum NonceMapError {
    NotFound,
    Expired,
    LockPoisoned,
}

/// Trait for converting `NonceMapError` to a domain-specific error type.
///
/// Implement this for each domain error (ChallengeError, RecoveryChallengeError,
/// TransferNonceError) to replace per-store `map_err` functions.
pub(crate) trait FromNonceMapError {
    fn from_nonce_map_error(e: NonceMapError) -> Self;
}

/// Generic in-memory nonce map.
///
/// Stores `(K) → DateTime<Utc>` entries with periodic cleanup.
pub(crate) struct InMemoryNonceMap<K: Eq + Hash + Clone> {
    entries: RwLock<HashMap<K, DateTime<Utc>>>,
    ttl: TtlCleanup,
}

impl<K: Eq + Hash + Clone> InMemoryNonceMap<K> {
    pub(crate) fn new(ttl: TtlCleanup) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    pub(crate) fn maybe_cleanup(&self) {
        let entries = &self.entries;
        self.ttl.maybe_cleanup(|| {
            let mut map = entries.write().unwrap_or_else(|e| e.into_inner());
            let now = Utc::now();
            map.retain(|_, expires_at| *expires_at > now);
        });
    }

    /// Store a nonce with an expiration time.
    pub(crate) fn store(&self, key: K, expires_at: DateTime<Utc>) -> Result<(), NonceMapError> {
        self.maybe_cleanup();
        let mut entries = self.entries.write().map_err(|_| NonceMapError::LockPoisoned)?;
        entries.insert(key, expires_at);
        Ok(())
    }

    /// Verify a nonce exists and is not expired (does NOT consume).
    pub(crate) fn verify(&self, key: &K) -> Result<(), NonceMapError> {
        self.maybe_cleanup();
        let entries = self.entries.read().map_err(|_| NonceMapError::LockPoisoned)?;
        match entries.get(key) {
            Some(expires_at) => {
                if *expires_at < Utc::now() {
                    Err(NonceMapError::Expired)
                } else {
                    Ok(())
                }
            }
            None => Err(NonceMapError::NotFound),
        }
    }

    /// Remove a nonce (does NOT check expiry).
    pub(crate) fn consume(&self, key: &K) -> Result<(), NonceMapError> {
        let mut entries = self.entries.write().map_err(|_| NonceMapError::LockPoisoned)?;
        match entries.remove(key) {
            Some(_) => Ok(()),
            None => Err(NonceMapError::NotFound),
        }
    }

    /// Atomically remove and verify a nonce.
    pub(crate) fn verify_and_remove(&self, key: &K) -> Result<(), NonceMapError> {
        self.maybe_cleanup();
        let mut entries = self.entries.write().map_err(|_| NonceMapError::LockPoisoned)?;
        match entries.remove(key) {
            Some(expires_at) => {
                if expires_at < Utc::now() {
                    Err(NonceMapError::Expired)
                } else {
                    Ok(())
                }
            }
            None => Err(NonceMapError::NotFound),
        }
    }
}
