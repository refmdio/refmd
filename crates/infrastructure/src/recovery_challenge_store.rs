//! Redis-backed recovery challenge store for HA mode
//!
//! Implements the RecoveryChallengeStore trait for cluster deployments.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use domain::recovery_challenge::{RecoveryChallengeError, RecoveryChallengeStore};

use crate::RedisPool;
use crate::redis_nonce_ops::FromRedisNonceError;

/// Redis-backed recovery challenge store for cluster deployments
///
/// Uses Redis keys with TTL for automatic expiration.
/// Key format: recovery_challenge:{email_hash}:{challenge_base64}
///
/// Note: We hash the email to avoid storing PII in Redis keys.
pub struct RedisRecoveryChallengeStore {
    redis: RedisPool,
}

impl RedisRecoveryChallengeStore {
    /// Create a new Redis recovery challenge store
    pub fn new(redis: RedisPool) -> Self {
        Self { redis }
    }

    /// Generate Redis key for a challenge
    ///
    /// Uses SHA256 hash of email to avoid storing PII in Redis keys.
    fn key(email: &str, challenge: &[u8; 32]) -> String {
        use sha2::{Digest, Sha256};
        let email_hash = Sha256::digest(email.to_lowercase().as_bytes());
        let email_hash_b64 = base64_url::encode(&email_hash[..16]); // Use first 16 bytes
        let challenge_b64 = base64_url::encode(challenge);
        format!("recovery_challenge:{}:{}", email_hash_b64, challenge_b64)
    }
}

impl_from_redis_nonce_error!(RecoveryChallengeError);

#[async_trait]
impl RecoveryChallengeStore for RedisRecoveryChallengeStore {
    async fn store(
        &self,
        email: &str,
        challenge: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), RecoveryChallengeError> {
        let key = Self::key(email, &challenge);
        redis_nonce_method!(store, &self.redis, &key, expires_at, RecoveryChallengeError)
    }

    async fn verify(
        &self,
        email: &str,
        challenge: &[u8; 32],
    ) -> Result<(), RecoveryChallengeError> {
        let key = Self::key(email, challenge);
        redis_nonce_method!(verify, &self.redis, &key, RecoveryChallengeError)
    }

    async fn consume(
        &self,
        email: &str,
        challenge: &[u8; 32],
    ) -> Result<(), RecoveryChallengeError> {
        let key = Self::key(email, challenge);
        redis_nonce_method!(consume, &self.redis, &key, RecoveryChallengeError)
    }
}
