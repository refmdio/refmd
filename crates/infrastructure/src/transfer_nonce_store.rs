//! Redis-backed transfer nonce store for HA mode
//!
//! Implements the TransferNonceStore trait for cluster deployments.
//!
//! # Requirements
//!
//! - **Redis 6.2+** required for atomic `GETDEL` command in `verify_and_consume()`

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use domain::encryption::DeviceId;
use domain::identity::UserId;
use domain::transfer_nonce::{TransferNonceError, TransferNonceStore};

use crate::RedisPool;
use crate::redis_nonce_ops::FromRedisNonceError;

/// Redis-backed transfer nonce store for cluster deployments
///
/// Uses Redis keys with TTL for automatic expiration.
/// Key format: trust_transfer:{user_id}:{device_id}:{nonce_base64}
pub struct RedisTransferNonceStore {
    redis: RedisPool,
}

impl RedisTransferNonceStore {
    /// Create a new Redis transfer nonce store
    pub fn new(redis: RedisPool) -> Self {
        Self { redis }
    }

    /// Generate Redis key for a transfer nonce
    fn key(user_id: UserId, device_id: DeviceId, nonce: &[u8; 32]) -> String {
        let nonce_b64 = base64_url::encode(nonce);
        format!(
            "trust_transfer:{}:{}:{}",
            user_id.as_uuid(),
            device_id.as_uuid(),
            nonce_b64
        )
    }
}

impl_from_redis_nonce_error!(TransferNonceError);

#[async_trait]
impl TransferNonceStore for RedisTransferNonceStore {
    async fn store(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        nonce: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), TransferNonceError> {
        let key = Self::key(user_id, new_device_id, &nonce);
        redis_nonce_method!(store, &self.redis, &key, expires_at, TransferNonceError)
    }

    async fn verify_and_consume(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        nonce: &[u8; 32],
    ) -> Result<(), TransferNonceError> {
        let key = Self::key(user_id, new_device_id, nonce);
        redis_nonce_method!(verify_and_consume, &self.redis, &key, TransferNonceError)
    }
}
