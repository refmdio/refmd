//! Cryptographic key validation utilities (presentation layer)
//!
//! Pure validation logic (constants, point checks) lives in `domain::crypto_validation`.
//! This module re-exports that logic and adds HTTP-specific helpers for request decoding.
//!
//! ## Defense-in-depth validation
//!
//! Both the presentation and application layers validate cryptographic inputs.
//! This is **intentional** defense-in-depth for E2EE security:
//!
//! - **Presentation layer** (here): decodes wire format (base64url), validates sizes,
//!   and rejects low-order/small-order points. Returns typed HTTP error responses.
//! - **Application layer**: re-validates byte lengths and cryptographic invariants
//!   as business-rule preconditions, independent of the transport layer.
//!
//! This ensures the application layer remains self-contained and safe to invoke
//! from non-HTTP contexts (e.g., tests, CLI, future gRPC) while the presentation
//! layer provides fast-fail with descriptive HTTP error messages.

// Re-export domain-layer crypto validation (via application facade)
pub use application::types::crypto_validation::*;

/// Maximum encrypted key size (256 bytes).
/// XChaCha20-Poly1305 wrapping a 32-byte key = 48 bytes; 256 is generous.
pub const MAX_ENCRYPTED_KEY_BYTES: usize = 256;

// =============================================================================
// Base64url decode helpers for request validation
// =============================================================================

use axum::http::StatusCode;

/// Decode a base64url field, returning `(StatusCode, String)` on error.
pub fn decode_b64(field: &str, val: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    base64_url::decode(val).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid {field} encoding"),
        )
    })
}

/// Decode a base64url field with a maximum decoded byte length.
///
/// Rejects payloads that exceed `max_bytes` after decoding to prevent DoS
/// via oversized encrypted payloads.
pub fn decode_b64_max(
    field: &str,
    val: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let bytes = decode_b64(field, val)?;
    if bytes.len() > max_bytes {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} too large: max {max_bytes} bytes"),
        ));
    }
    Ok(bytes)
}

/// Decode a base64url field and verify exact byte length.
pub fn decode_b64_exact(
    field: &str,
    val: &str,
    size: usize,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let bytes = decode_b64(field, val)?;
    if bytes.len() != size {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("invalid {field} length: expected {size} bytes"),
        ));
    }
    Ok(bytes)
}

/// Decode and validate an X25519 public key (32 bytes, no low-order points).
pub fn decode_x25519_key(field: &str, val: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let bytes = decode_b64_exact(field, val, X25519_PUBLIC_KEY_SIZE)?;
    if !is_valid_x25519_public_key(&bytes) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("invalid {field}: low-order point rejected"),
        ));
    }
    Ok(bytes)
}

/// Decode and validate an Ed25519 public key (32 bytes, no small-order points).
pub fn decode_ed25519_key(field: &str, val: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let bytes = decode_b64_exact(field, val, ED25519_PUBLIC_KEY_SIZE)?;
    if !is_valid_ed25519_public_key(&bytes) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("invalid {field}: small-order point rejected"),
        ));
    }
    Ok(bytes)
}

/// Decode a 24-byte XChaCha20-Poly1305 nonce.
pub fn decode_nonce(field: &str, val: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    decode_b64_exact(field, val, 24)
}

/// Decode an encrypted key + nonce pair in one call.
///
/// Combines `decode_b64_max` (for the key) and `decode_nonce` (for the nonce)
/// into a single helper to reduce boilerplate in route handlers.
pub fn decode_encrypted_key_nonce(
    key_field: &str,
    key_val: &str,
    max_key_bytes: usize,
    nonce_field: &str,
    nonce_val: &str,
) -> Result<(Vec<u8>, Vec<u8>), (StatusCode, String)> {
    let key = decode_b64_max(key_field, key_val, max_key_bytes)?;
    let nonce = decode_nonce(nonce_field, nonce_val)?;
    Ok((key, nonce))
}

/// Decode a 64-byte Ed25519 signature.
pub fn decode_signature(field: &str, val: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    decode_b64_exact(field, val, 64)
}

/// Decode base64url and return a fixed-size byte array.
pub fn decode_b64_array<const N: usize>(
    field: &str,
    val: &str,
) -> Result<[u8; N], (StatusCode, String)> {
    let bytes = decode_b64_exact(field, val, N)?;
    bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid {field} length: expected {N} bytes"),
        )
    })
}

/// Parse a device type string ("browser", "desktop", "mobile").
pub fn parse_device_type(
    val: &str,
) -> Result<application::types::DeviceType, (StatusCode, String)> {
    val.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "invalid device_type: must be 'browser', 'desktop', or 'mobile'".to_string(),
        )
    })
}

/// Parse a UUID string field, returning `(StatusCode, String)` on error.
pub fn parse_uuid(field: &str, val: &str) -> Result<uuid::Uuid, (StatusCode, String)> {
    uuid::Uuid::parse_str(val).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid {field} format"),
        )
    })
}

/// Parse a UUID string field into a DeviceId.
pub fn parse_device_id(
    field: &str,
    val: &str,
) -> Result<application::types::DeviceId, (StatusCode, String)> {
    let uuid = parse_uuid(field, val)?;
    Ok(application::types::DeviceId::from_uuid(uuid))
}

/// Helper macro to decode a crypto field, returning an HTTP error response on failure.
///
/// Usage: `let val = try_decode!(decode_nonce("nonce", &req.nonce), ErrorResponseType);`
#[macro_export]
macro_rules! try_decode {
    ($result:expr, $resp_type:ident) => {
        match $result {
            Ok(v) => v,
            Err((status, msg)) => {
                return (status, axum::Json($resp_type { error: msg })).into_response()
            }
        }
    };
}

/// Map a decode `(StatusCode, String)` error into an axum `Response`.
///
/// Unlike `try_decode!` (which does an early return), this maps the error
/// for use in validation functions that return `Result<T, Response>`.
///
/// Usage: `decode_b64("field", val).map_err(map_decode_response!(ErrorResponseType))?;`
#[macro_export]
macro_rules! map_decode_response {
    ($resp_type:ident) => {
        |(status, msg): (axum::http::StatusCode, String)| -> axum::response::Response {
            use axum::response::IntoResponse;
            (status, axum::Json($resp_type { error: msg })).into_response()
        }
    };
}
