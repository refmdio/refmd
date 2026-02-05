//! Redis-backed transfer state store for HA mode
//!
//! Implements the TransferStateStore trait for cluster deployments.
//! Stores encrypted trust state temporarily while the new device retrieves it.
//!
//! # Requirements
//!
//! - **Redis 6.2+** required for atomic `GETDEL` command in `retrieve_and_consume()`

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use domain::encryption::DeviceId;
use domain::identity::UserId;
use domain::transfer_nonce::{EncryptedTransferState, TransferStateError, TransferStateStore};

use crate::RedisPool;

/// Serializable form of EncryptedTransferState for Redis storage
#[derive(Serialize, Deserialize)]
struct SerializedTransferState {
    /// Base64url encoded ciphertext
    ciphertext: String,
    /// Base64url encoded nonce (24 bytes)
    nonce: String,
    /// Base64url encoded signature (64 bytes)
    signature: String,
    /// Sender device ID (UUID string)
    sender_device_id: String,
    /// Expiration timestamp
    expires_at: i64,
}

/// Redis-backed transfer state store for cluster deployments
///
/// Uses Redis keys with TTL for automatic expiration.
/// Key format: trust_state:{user_id}:{device_id}
pub struct RedisTransferStateStore {
    redis: RedisPool,
}

impl RedisTransferStateStore {
    /// Create a new Redis transfer state store
    pub fn new(redis: RedisPool) -> Self {
        Self { redis }
    }

    /// Generate Redis key for transfer state
    fn key(user_id: UserId, device_id: DeviceId) -> String {
        format!(
            "trust_state:{}:{}",
            user_id.as_uuid(),
            device_id.as_uuid()
        )
    }
}

#[async_trait]
impl TransferStateStore for RedisTransferStateStore {
    async fn store(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
        state: EncryptedTransferState,
        expires_at: DateTime<Utc>,
    ) -> Result<(), TransferStateError> {
        let key = Self::key(user_id, new_device_id);
        let ttl_secs = (expires_at - Utc::now()).num_seconds().max(1) as u64;

        let serialized = SerializedTransferState {
            ciphertext: base64_url::encode(&state.ciphertext),
            nonce: base64_url::encode(&state.nonce),
            signature: base64_url::encode(&state.signature),
            sender_device_id: state.sender_device_id.as_uuid().to_string(),
            expires_at: expires_at.timestamp(),
        };

        let json = serde_json::to_string(&serialized).map_err(|e| {
            tracing::error!("Failed to serialize transfer state: {}", e);
            TransferStateError::StoreError
        })?;

        let mut conn = self.redis.connection();
        let _: () = conn.set_ex(&key, json, ttl_secs).await.map_err(|e| {
            tracing::error!("Redis transfer state store error: {}", e);
            TransferStateError::StoreError
        })?;

        Ok(())
    }

    async fn retrieve_and_consume(
        &self,
        user_id: UserId,
        new_device_id: DeviceId,
    ) -> Result<EncryptedTransferState, TransferStateError> {
        let key = Self::key(user_id, new_device_id);
        let mut conn = self.redis.connection();

        // Use GETDEL for atomic get-and-delete (Redis 6.2+)
        let result: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("Redis transfer state GETDEL error: {}", e);
                TransferStateError::StoreError
            })?;

        let json = result.ok_or(TransferStateError::NotFound)?;

        let serialized: SerializedTransferState =
            serde_json::from_str(&json).map_err(|e| {
                tracing::error!("Failed to deserialize transfer state: {}", e);
                TransferStateError::StoreError
            })?;

        // Check expiration
        let expires_at = DateTime::from_timestamp(serialized.expires_at, 0)
            .ok_or(TransferStateError::StoreError)?;
        if expires_at < Utc::now() {
            return Err(TransferStateError::NotFound);
        }

        // Decode fields
        let ciphertext = base64_url::decode(&serialized.ciphertext).map_err(|e| {
            tracing::error!("Failed to decode ciphertext: {}", e);
            TransferStateError::StoreError
        })?;

        let nonce_vec = base64_url::decode(&serialized.nonce).map_err(|e| {
            tracing::error!("Failed to decode nonce: {}", e);
            TransferStateError::StoreError
        })?;
        let nonce: [u8; 24] = nonce_vec.try_into().map_err(|_| {
            tracing::error!("Invalid nonce length");
            TransferStateError::StoreError
        })?;

        let signature_vec = base64_url::decode(&serialized.signature).map_err(|e| {
            tracing::error!("Failed to decode signature: {}", e);
            TransferStateError::StoreError
        })?;
        let signature: [u8; 64] = signature_vec.try_into().map_err(|_| {
            tracing::error!("Invalid signature length");
            TransferStateError::StoreError
        })?;

        let sender_device_id =
            uuid::Uuid::parse_str(&serialized.sender_device_id).map_err(|e| {
                tracing::error!("Failed to parse sender device ID: {}", e);
                TransferStateError::StoreError
            })?;

        Ok(EncryptedTransferState {
            ciphertext,
            nonce,
            signature,
            sender_device_id: DeviceId::from_uuid(sender_device_id),
        })
    }
}
