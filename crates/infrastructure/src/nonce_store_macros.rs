//! Declarative macros for nonce store error conversions
//!
//! Eliminates boilerplate `FromRedisNonceError` / `FromNonceMapError` impls
//! across the 6 nonce store files (3 Redis + 3 in-memory).

/// Implement `FromRedisNonceError` for a domain error type.
///
/// Requires the error type to have `NotFound`, `Expired`, and `StoreError` variants.
macro_rules! impl_from_redis_nonce_error {
    ($error_type:ty) => {
        impl $crate::redis_nonce_ops::FromRedisNonceError for $error_type {
            fn from_redis_nonce_error(
                e: $crate::redis_nonce_ops::RedisNonceError,
            ) -> Self {
                match e {
                    $crate::redis_nonce_ops::RedisNonceError::NotFound => <$error_type>::NotFound,
                    $crate::redis_nonce_ops::RedisNonceError::Expired => <$error_type>::Expired,
                    $crate::redis_nonce_ops::RedisNonceError::StoreError => {
                        <$error_type>::StoreError
                    }
                }
            }
        }
    };
}

/// Call a Redis nonce operation and map the error via `FromRedisNonceError`.
///
/// Variants:
/// - `store`: `redis_store_nonce(redis, key, expires_at)`
/// - `verify`: `redis_verify_nonce(redis, key)`
/// - `consume`: `redis_consume_nonce(redis, key)`
/// - `verify_and_consume`: `redis_verify_and_consume_nonce(redis, key)`
macro_rules! redis_nonce_method {
    (store, $redis:expr, $key:expr, $expires_at:expr, $err:ty) => {
        $crate::redis_nonce_ops::redis_store_nonce($redis, $key, $expires_at)
            .await
            .map_err(<$err>::from_redis_nonce_error)
    };
    (verify, $redis:expr, $key:expr, $err:ty) => {
        $crate::redis_nonce_ops::redis_verify_nonce($redis, $key)
            .await
            .map_err(<$err>::from_redis_nonce_error)
    };
    (consume, $redis:expr, $key:expr, $err:ty) => {
        $crate::redis_nonce_ops::redis_consume_nonce($redis, $key)
            .await
            .map_err(<$err>::from_redis_nonce_error)
    };
    (verify_and_consume, $redis:expr, $key:expr, $err:ty) => {
        $crate::redis_nonce_ops::redis_verify_and_consume_nonce($redis, $key)
            .await
            .map_err(<$err>::from_redis_nonce_error)
    };
}

/// Implement `FromNonceMapError` for a domain error type.
///
/// Requires the error type to have `NotFound`, `Expired`, and `StoreError` variants.
macro_rules! impl_from_nonce_map_error {
    ($error_type:ty) => {
        impl $crate::in_memory_nonce_map::FromNonceMapError for $error_type {
            fn from_nonce_map_error(
                e: $crate::in_memory_nonce_map::NonceMapError,
            ) -> Self {
                match e {
                    $crate::in_memory_nonce_map::NonceMapError::NotFound => {
                        <$error_type>::NotFound
                    }
                    $crate::in_memory_nonce_map::NonceMapError::Expired => {
                        <$error_type>::Expired
                    }
                    $crate::in_memory_nonce_map::NonceMapError::LockPoisoned => {
                        <$error_type>::StoreError
                    }
                }
            }
        }
    };
}
