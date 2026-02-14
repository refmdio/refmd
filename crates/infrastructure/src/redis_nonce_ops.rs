//! Shared Redis nonce operations for challenge and transfer nonce stores
//!
//! Encapsulates the common store/verify/consume/verify_and_consume pattern
//! used by `RedisChallengeStore`, `RedisRecoveryChallengeStore`, and
//! `RedisTransferNonceStore`.

use chrono::{DateTime, Utc};
use redis::AsyncCommands;

use crate::RedisPool;

/// Error from Redis nonce operations
#[derive(Debug)]
pub(crate) enum RedisNonceError {
    NotFound,
    Expired,
    StoreError,
}

/// Trait for converting `RedisNonceError` to a domain-specific error type.
///
/// Implement this for each domain error (ChallengeError, RecoveryChallengeError,
/// TransferNonceError) to replace per-store `map_err` functions.
pub(crate) trait FromRedisNonceError {
    fn from_redis_nonce_error(e: RedisNonceError) -> Self;
}

/// Store a nonce in Redis with TTL-based expiration.
pub(crate) async fn redis_store_nonce(
    pool: &RedisPool,
    key: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), RedisNonceError> {
    let ttl_secs = (expires_at - Utc::now()).num_seconds().max(1) as u64;
    let mut conn = pool.connection();
    let _: () = conn
        .set_ex(key, expires_at.timestamp(), ttl_secs)
        .await
        .map_err(|e| {
            tracing::error!("Redis nonce store error: {}", e);
            RedisNonceError::StoreError
        })?;
    Ok(())
}

/// Verify a nonce exists and is valid (does NOT consume).
pub(crate) async fn redis_verify_nonce(
    pool: &RedisPool,
    key: &str,
) -> Result<(), RedisNonceError> {
    let mut conn = pool.connection();
    let result: Option<i64> = conn
        .get(key)
        .await
        .map_err(|_| RedisNonceError::StoreError)?;

    match result {
        Some(expires_timestamp) => {
            let expires_at = DateTime::from_timestamp(expires_timestamp, 0)
                .ok_or(RedisNonceError::StoreError)?;
            if expires_at < Utc::now() {
                Err(RedisNonceError::Expired)
            } else {
                Ok(())
            }
        }
        None => Err(RedisNonceError::NotFound),
    }
}

/// Consume (remove) a nonce without checking expiry.
pub(crate) async fn redis_consume_nonce(
    pool: &RedisPool,
    key: &str,
) -> Result<(), RedisNonceError> {
    let mut conn = pool.connection();
    let deleted: i32 = conn
        .del(key)
        .await
        .map_err(|_| RedisNonceError::StoreError)?;

    if deleted > 0 {
        Ok(())
    } else {
        Err(RedisNonceError::NotFound)
    }
}

/// Atomically get-and-delete a nonce, verifying expiry.
///
/// Requires Redis 6.2+ for the `GETDEL` command.
pub(crate) async fn redis_verify_and_consume_nonce(
    pool: &RedisPool,
    key: &str,
) -> Result<(), RedisNonceError> {
    let mut conn = pool.connection();
    let result: Option<i64> = redis::cmd("GETDEL")
        .arg(key)
        .query_async(&mut conn)
        .await
        .map_err(|e| {
            tracing::error!("Redis GETDEL error: {}", e);
            RedisNonceError::StoreError
        })?;

    match result {
        Some(expires_timestamp) => {
            let expires_at = DateTime::from_timestamp(expires_timestamp, 0)
                .ok_or(RedisNonceError::StoreError)?;
            if expires_at < Utc::now() {
                Err(RedisNonceError::Expired)
            } else {
                Ok(())
            }
        }
        None => Err(RedisNonceError::NotFound),
    }
}
