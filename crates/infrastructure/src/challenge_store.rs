//! Redis-backed challenge store for HA mode
//!
//! Implements the ChallengeStore trait for cluster deployments.
//!
//! # Requirements
//!
//! - **Redis 6.2+** required for atomic `GETDEL` command in `verify_and_remove()`

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use domain::encryption::DeviceId;
use domain::pop::{ChallengeError, ChallengeStore};

use crate::RedisPool;
use crate::redis_nonce_ops::FromRedisNonceError;

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

impl_from_redis_nonce_error!(ChallengeError);

#[async_trait]
impl ChallengeStore for RedisChallengeStore {
    async fn store(
        &self,
        device_id: DeviceId,
        challenge: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), ChallengeError> {
        let key = Self::key(device_id, &challenge);
        redis_nonce_method!(store, &self.redis, &key, expires_at, ChallengeError)
    }

    async fn verify(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        let key = Self::key(device_id, challenge);
        redis_nonce_method!(verify, &self.redis, &key, ChallengeError)
    }

    async fn consume(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        let key = Self::key(device_id, challenge);
        redis_nonce_method!(consume, &self.redis, &key, ChallengeError)
    }

    async fn verify_and_remove(
        &self,
        device_id: DeviceId,
        challenge: &[u8; 32],
    ) -> Result<(), ChallengeError> {
        let key = Self::key(device_id, challenge);
        redis_nonce_method!(verify_and_consume, &self.redis, &key, ChallengeError)
    }
}
