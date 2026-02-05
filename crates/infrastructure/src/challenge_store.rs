//! Redis-backed challenge store for HA mode
//!
//! Implements the ChallengeStore trait for cluster deployments.
//!
//! # Requirements
//!
//! - **Redis 6.2+** required for atomic `GETDEL` command in `verify_and_remove()`

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::AsyncCommands;

use domain::encryption::DeviceId;
use domain::pop::{ChallengeError, ChallengeStore};

use crate::RedisPool;

/// Redis-backed challenge store for cluster deployments
///
/// Uses Redis keys with TTL for automatic expiration.
/// Key format: pop_challenge:{device_id}:{challenge_base64}
pub struct RedisChallengeStore {
    redis: RedisPool,
}

impl RedisChallengeStore {
    /// Create a new Redis challenge store
    pub fn new(redis: RedisPool) -> Self {
        Self { redis }
    }

    /// Generate Redis key for a challenge
    fn key(device_id: DeviceId, challenge: &[u8; 32]) -> String {
        let challenge_b64 = base64_url::encode(challenge);
        format!("pop_challenge:{}:{}", device_id.as_uuid(), challenge_b64)
    }
}

#[async_trait]
impl ChallengeStore for RedisChallengeStore {
    async fn store(
        &self,
        device_id: DeviceId,
        challenge: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), ChallengeError> {
        let key = Self::key(device_id, &challenge);
        let ttl_secs = (expires_at - Utc::now()).num_seconds().max(1) as u64;

        let mut conn = self.redis.connection();
        // Store timestamp as value, with TTL
        let _: () = conn
            .set_ex(&key, expires_at.timestamp(), ttl_secs)
            .await
            .map_err(|e| {
                tracing::error!("Redis store error: {}", e);
                ChallengeError::StoreError
            })?;
        Ok(())
    }

    async fn verify(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        let key = Self::key(device_id, challenge);
        let mut conn = self.redis.connection();

        let result: Option<i64> = conn
            .get(&key)
            .await
            .map_err(|_| ChallengeError::StoreError)?;

        match result {
            Some(expires_timestamp) => {
                let expires_at = DateTime::from_timestamp(expires_timestamp, 0)
                    .ok_or(ChallengeError::StoreError)?;
                if expires_at < Utc::now() {
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
        let key = Self::key(device_id, challenge);
        let mut conn = self.redis.connection();

        // DEL returns number of keys deleted
        let deleted: i32 = conn
            .del(&key)
            .await
            .map_err(|_| ChallengeError::StoreError)?;

        if deleted > 0 {
            Ok(())
        } else {
            Err(ChallengeError::NotFound)
        }
    }

    async fn verify_and_remove(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        let key = Self::key(device_id, challenge);
        let mut conn = self.redis.connection();

        // Use GETDEL for atomic get-and-delete (Redis 6.2+)
        let result: Option<i64> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("Redis GETDEL error: {}", e);
                ChallengeError::StoreError
            })?;

        match result {
            Some(expires_timestamp) => {
                let expires_at = DateTime::from_timestamp(expires_timestamp, 0)
                    .ok_or(ChallengeError::StoreError)?;
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
