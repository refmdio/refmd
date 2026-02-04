//! Proof of Possession (PoP) verification middleware
//!
//! ADR-009 compliant: Verifies device ownership via cryptographic signature.
//!
//! Headers required:
//! - X-PoP-Nonce: 32 bytes base64url encoded random nonce
//! - X-PoP-Signature: Ed25519 signature of nonce by device signing key
//! - X-PoP-Device-Id: Device UUID

use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use uuid::Uuid;

use application::domain::encryption::{DeviceId, DeviceRepository};

/// PoP header names
pub const POP_NONCE_HEADER: &str = "X-PoP-Nonce";
pub const POP_SIGNATURE_HEADER: &str = "X-PoP-Signature";
pub const POP_DEVICE_ID_HEADER: &str = "X-PoP-Device-Id";

/// Error response for PoP failures
#[derive(Debug, Serialize)]
pub struct PopError {
    pub error: String,
}

/// Nonce cache for replay attack prevention
pub struct NonceCache {
    nonces: RwLock<HashSet<String>>,
    ttl: Duration,
    last_cleanup: RwLock<Instant>,
}

impl NonceCache {
    /// Create a new nonce cache with the given TTL
    pub fn new(ttl: Duration) -> Self {
        Self {
            nonces: RwLock::new(HashSet::new()),
            ttl,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Check if nonce exists (replay attack detection)
    /// Returns true if the nonce is new (not seen before)
    pub fn check_and_store(&self, nonce: &str) -> bool {
        // Cleanup old entries periodically
        self.maybe_cleanup();

        let mut nonces = self.nonces.write().unwrap();

        // Check if nonce already exists
        if nonces.contains(nonce) {
            return false;
        }

        // Store new nonce
        nonces.insert(nonce.to_string());
        true
    }

    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let last = self.last_cleanup.read().unwrap();
            now.duration_since(*last) > self.ttl
        };

        if should_cleanup {
            let mut nonces = self.nonces.write().unwrap();
            let mut last = self.last_cleanup.write().unwrap();

            // Clear all nonces (simple strategy - old nonces expire after TTL)
            nonces.clear();
            *last = now;
        }
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(300)) // 5 minute TTL
    }
}

/// Extract and validate PoP headers
pub fn extract_pop_headers(
    req: &Request,
) -> Result<(Vec<u8>, Vec<u8>, Uuid), PopError> {
    // Extract nonce
    let nonce_header = req
        .headers()
        .get(POP_NONCE_HEADER)
        .ok_or_else(|| PopError {
            error: format!("missing {} header", POP_NONCE_HEADER),
        })?;

    let nonce_str = nonce_header.to_str().map_err(|_| PopError {
        error: format!("invalid {} header encoding", POP_NONCE_HEADER),
    })?;

    let nonce = base64_url::decode(nonce_str).map_err(|_| PopError {
        error: "invalid nonce encoding".to_string(),
    })?;

    if nonce.len() != 32 {
        return Err(PopError {
            error: "nonce must be 32 bytes".to_string(),
        });
    }

    // Extract signature
    let sig_header = req
        .headers()
        .get(POP_SIGNATURE_HEADER)
        .ok_or_else(|| PopError {
            error: format!("missing {} header", POP_SIGNATURE_HEADER),
        })?;

    let sig_str = sig_header.to_str().map_err(|_| PopError {
        error: format!("invalid {} header encoding", POP_SIGNATURE_HEADER),
    })?;

    let signature = base64_url::decode(sig_str).map_err(|_| PopError {
        error: "invalid signature encoding".to_string(),
    })?;

    if signature.len() != 64 {
        return Err(PopError {
            error: "signature must be 64 bytes".to_string(),
        });
    }

    // Extract device ID
    let device_id_header = req
        .headers()
        .get(POP_DEVICE_ID_HEADER)
        .ok_or_else(|| PopError {
            error: format!("missing {} header", POP_DEVICE_ID_HEADER),
        })?;

    let device_id_str = device_id_header.to_str().map_err(|_| PopError {
        error: format!("invalid {} header encoding", POP_DEVICE_ID_HEADER),
    })?;

    let device_id = Uuid::parse_str(device_id_str).map_err(|_| PopError {
        error: "invalid device ID format".to_string(),
    })?;

    Ok((nonce, signature, device_id))
}

/// Verify PoP signature using Ed25519
pub fn verify_pop_signature(
    nonce: &[u8],
    signature: &[u8],
    signing_public_key: &[u8],
) -> Result<(), PopError> {
    // Parse public key
    let pk_bytes: [u8; 32] = signing_public_key.try_into().map_err(|_| PopError {
        error: "invalid public key length".to_string(),
    })?;

    let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| PopError {
        error: "invalid public key".to_string(),
    })?;

    // Parse signature
    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| PopError {
        error: "invalid signature length".to_string(),
    })?;

    let sig = Signature::from_bytes(&sig_bytes);

    // Verify
    verifying_key.verify(nonce, &sig).map_err(|_| PopError {
        error: "invalid signature".to_string(),
    })
}

/// PoP verification middleware
///
/// Verifies device ownership via cryptographic signature on nonce
pub async fn require_pop<D>(
    device_repo: Arc<D>,
    nonce_cache: Arc<NonceCache>,
    req: Request,
    next: Next,
) -> Response
where
    D: DeviceRepository + Send + Sync + 'static,
{
    // Extract PoP headers
    let (nonce, signature, device_id) = match extract_pop_headers(&req) {
        Ok(h) => h,
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, Json(e)).into_response();
        }
    };

    // Check nonce hasn't been used (replay attack prevention)
    let nonce_key = base64_url::encode(&nonce);
    if !nonce_cache.check_and_store(&nonce_key) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(PopError {
                error: "nonce already used (possible replay attack)".to_string(),
            }),
        )
            .into_response();
    }

    // Fetch device
    let device = match device_repo.find_by_id(DeviceId::from_uuid(device_id)).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(PopError {
                    error: "device not found".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PopError {
                    error: "internal server error".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Check device is not revoked
    if device.is_revoked() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(PopError {
                error: "device has been revoked".to_string(),
            }),
        )
            .into_response();
    }

    // Verify signature
    if let Err(e) = verify_pop_signature(&nonce, &signature, &device.signing_public_key) {
        return (StatusCode::UNAUTHORIZED, Json(e)).into_response();
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_cache_prevents_replay() {
        let cache = NonceCache::new(Duration::from_secs(60));

        let nonce = "test_nonce_123";

        // First use should succeed
        assert!(cache.check_and_store(nonce));

        // Second use should fail (replay)
        assert!(!cache.check_and_store(nonce));
    }

    #[test]
    fn test_nonce_cache_allows_different_nonces() {
        let cache = NonceCache::new(Duration::from_secs(60));

        assert!(cache.check_and_store("nonce1"));
        assert!(cache.check_and_store("nonce2"));
        assert!(cache.check_and_store("nonce3"));
    }
}
