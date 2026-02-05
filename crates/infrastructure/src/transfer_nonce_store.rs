//! Redis-backed transfer nonce store for HA mode
//!
//! Implements the TransferNonceStore trait for cluster deployments.
//!
//! # Requirements
//!
//! - **Redis 6.2+** required for atomic `GETDEL` command in `verify_and_consume()`

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::AsyncCommands;

use domain::encryption::DeviceId;
use domain::identity::UserId;
use domain::transfer_nonce::{TransferNonceError, TransferNonceStore};

use crate::RedisPool;

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
        let ttl_secs = (expires_at - Utc::now()).num_seconds().max(1) as u64;

        let mut conn = self.redis.connection();
        // Store timestamp as value, with TTL
        let _: () = conn
            .set_ex(&key, expires_at.timestamp(), ttl_secs)
            .await
            .map_err(|e| {
                tracing::error!("Redis transfer nonce store error: {}", e);
                TransferNonceError::StoreError
            })?;
        Ok(())
    }

    async fn verify_and_consume(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        nonce: &[u8; 32],
    ) -> Result<(), TransferNonceError> {
        let key = Self::key(user_id, new_device_id, nonce);
        let mut conn = self.redis.connection();

        // Use GETDEL for atomic get-and-delete (Redis 6.2+)
        let result: Option<i64> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("Redis transfer nonce GETDEL error: {}", e);
                TransferNonceError::StoreError
            })?;

        match result {
            Some(expires_timestamp) => {
                let expires_at = DateTime::from_timestamp(expires_timestamp, 0)
                    .ok_or(TransferNonceError::StoreError)?;
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
