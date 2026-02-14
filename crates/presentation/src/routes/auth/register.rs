//! Registration endpoint

use crate::crypto_validation::{
    decode_b64_exact, decode_b64_max, decode_ed25519_key, decode_x25519_key,
    MAX_ENCRYPTED_KEY_BYTES,
};
use crate::map_decode_response;

/// XChaCha20-Poly1305 nonce size in bytes
const XCHACHA20_NONCE_SIZE: usize = 24;

/// Argon2id salt size in bytes (per spec)
const ARGON2_SALT_SIZE: usize = 16;

/// Client nonce size in bytes (for SAS verification)
const CLIENT_NONCE_SIZE: usize = 16;

/// Ed25519 signature size in bytes
const ED25519_SIGNATURE_SIZE: usize = 64;

use application::types::DeviceType;
use application::identity::{
    RegisterPasswordUserAtomicCommand, RegisterPasswordUserAtomicHandler,
};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AuthSubState;
use crate::routes::app_error_response;
use super::AuthErrorResponse;

/// Register password user request
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// Client-generated User ID (UUID) - required for AAD binding
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: uuid::Uuid,
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User display name
    #[schema(example = "John Doe")]
    pub name: String,
    /// authKey for login (base64url encoded)
    #[schema(example = "base64url-encoded-auth-key")]
    pub auth_key: String,
    /// Salt for KDF (base64url encoded, 16 bytes per spec)
    #[schema(example = "base64url-encoded-salt")]
    pub salt: String,
    /// Encrypted UMK (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-umk")]
    pub encrypted_umk: String,
    /// UMK nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub umk_nonce: String,
    /// Recovery encrypted UMK (base64url encoded)
    #[schema(example = "base64url-encoded-recovery-encrypted-umk")]
    pub recovery_encrypted_umk: String,
    /// Recovery nonce (base64url encoded)
    #[schema(example = "base64url-encoded-recovery-nonce")]
    pub recovery_nonce: String,
    /// ECDH public key (base64url encoded, 32 bytes)
    #[schema(example = "base64url-encoded-ecdh-public-key")]
    pub ecdh_public_key: String,
    /// Signing public key (base64url encoded, 32 bytes)
    #[schema(example = "base64url-encoded-signing-public-key")]
    pub signing_public_key: String,
    /// Encrypted ECDH private key (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-ecdh-private")]
    pub encrypted_ecdh_private: String,
    /// Encrypted ECDH private key nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub encrypted_ecdh_private_nonce: String,
    /// Encrypted signing private key (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-signing-private")]
    pub encrypted_signing_private: String,
    /// Encrypted signing private key nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub encrypted_signing_private_nonce: String,
    /// Device name for the first device
    #[schema(example = "Chrome on MacOS")]
    pub device_name: String,
    /// Device type: "browser", "desktop", or "mobile"
    #[schema(example = "browser")]
    pub device_type: String,
    /// Device ECDH public key (base64url encoded, 32 bytes)
    #[schema(example = "base64url-encoded-device-ecdh-public-key")]
    pub device_ecdh_public_key: String,
    /// Device signing public key (base64url encoded, 32 bytes)
    #[schema(example = "base64url-encoded-device-signing-public-key")]
    pub device_signing_public_key: String,
    /// Device client nonce for SAS (base64url encoded, 16 bytes)
    #[schema(example = "base64url-encoded-device-nonce")]
    pub device_client_nonce: String,
    /// Identity signature over device keys (base64url encoded, 64 bytes Ed25519 signature)
    #[schema(example = "base64url-encoded-identity-signature")]
    pub device_identity_signature: String,
}

/// Register response
#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterResponse {
    /// User ID (UUID)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub id: String,
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Device ID (UUID) - the first registered device
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub device_id: String,
}

// =============================================================================
// Register request validation
// =============================================================================

struct ValidatedRegisterFields {
    salt: Vec<u8>,
    encrypted_umk: Vec<u8>,
    umk_nonce: Vec<u8>,
    recovery_encrypted_umk: Vec<u8>,
    recovery_nonce: Vec<u8>,
    ecdh_public_key: Vec<u8>,
    signing_public_key: Vec<u8>,
    encrypted_ecdh_private: Vec<u8>,
    encrypted_ecdh_private_nonce: Vec<u8>,
    encrypted_signing_private: Vec<u8>,
    encrypted_signing_private_nonce: Vec<u8>,
    device_ecdh_public_key: Vec<u8>,
    device_signing_public_key: Vec<u8>,
    device_client_nonce: Vec<u8>,
    device_identity_signature: Vec<u8>,
    device_type: DeviceType,
}

/// Shorthand: apply `map_decode_response!(AuthErrorResponse)` + `?` in one step.
macro_rules! dec {
    ($decode_call:expr) => {
        $decode_call.map_err(map_decode_response!(AuthErrorResponse))?
    };
}

#[allow(clippy::result_large_err)] // Response is standard axum type
fn validate_register_request(
    request: &RegisterRequest,
) -> Result<ValidatedRegisterFields, Response> {
    let device_type: DeviceType =
        dec!(crate::crypto_validation::parse_device_type(&request.device_type));

    Ok(ValidatedRegisterFields {
        salt: dec!(decode_b64_exact("salt", &request.salt, ARGON2_SALT_SIZE)),
        encrypted_umk: dec!(decode_b64_max("encrypted_umk", &request.encrypted_umk, MAX_ENCRYPTED_KEY_BYTES)),
        umk_nonce: dec!(decode_b64_exact("umk_nonce", &request.umk_nonce, XCHACHA20_NONCE_SIZE)),
        recovery_encrypted_umk: dec!(decode_b64_max("recovery_encrypted_umk", &request.recovery_encrypted_umk, MAX_ENCRYPTED_KEY_BYTES)),
        recovery_nonce: dec!(decode_b64_exact("recovery_nonce", &request.recovery_nonce, XCHACHA20_NONCE_SIZE)),
        ecdh_public_key: dec!(decode_x25519_key("ecdh_public_key", &request.ecdh_public_key)),
        signing_public_key: dec!(decode_ed25519_key("signing_public_key", &request.signing_public_key)),
        encrypted_ecdh_private: dec!(decode_b64_max("encrypted_ecdh_private", &request.encrypted_ecdh_private, MAX_ENCRYPTED_KEY_BYTES)),
        encrypted_ecdh_private_nonce: dec!(decode_b64_exact("encrypted_ecdh_private_nonce", &request.encrypted_ecdh_private_nonce, XCHACHA20_NONCE_SIZE)),
        encrypted_signing_private: dec!(decode_b64_max("encrypted_signing_private", &request.encrypted_signing_private, MAX_ENCRYPTED_KEY_BYTES)),
        encrypted_signing_private_nonce: dec!(decode_b64_exact("encrypted_signing_private_nonce", &request.encrypted_signing_private_nonce, XCHACHA20_NONCE_SIZE)),
        device_ecdh_public_key: dec!(decode_x25519_key("device_ecdh_public_key", &request.device_ecdh_public_key)),
        device_signing_public_key: dec!(decode_ed25519_key("device_signing_public_key", &request.device_signing_public_key)),
        device_client_nonce: dec!(decode_b64_exact("device_client_nonce", &request.device_client_nonce, CLIENT_NONCE_SIZE)),
        device_identity_signature: dec!(decode_b64_exact("device_identity_signature", &request.device_identity_signature, ED25519_SIGNATURE_SIZE)),
        device_type,
    })
}

/// Register a new password user
///
/// Creates a new user account with password authentication and E2EE keys.
/// All encryption is performed client-side; server stores encrypted data only.
/// Registration is atomic - all entities are created in a single transaction.
#[utoipa::path(
    post,
    path = "/api/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = RegisterResponse),
        (status = 400, description = "Invalid request", body = AuthErrorResponse),
        (status = 409, description = "Email already exists", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn register(
    State(state): State<AuthSubState>,
    Json(request): Json<RegisterRequest>,
) -> impl IntoResponse {
    let fields = match validate_register_request(&request) {
        Ok(f) => f,
        Err(response) => return response,
    };

    let handler = RegisterPasswordUserAtomicHandler::new(
        state.user_repo.clone(),
        state.workspace_repo.clone(),
        state.registration_service.clone(),
    );

    let command = RegisterPasswordUserAtomicCommand {
        user_id: request.user_id,
        email: request.email.clone(),
        name: request.name,
        auth_key: request.auth_key,
        salt: fields.salt,
        encrypted_umk: fields.encrypted_umk,
        umk_nonce: fields.umk_nonce,
        recovery_encrypted_umk: fields.recovery_encrypted_umk,
        recovery_nonce: fields.recovery_nonce,
        ecdh_public_key: fields.ecdh_public_key,
        signing_public_key: fields.signing_public_key,
        encrypted_ecdh_private: fields.encrypted_ecdh_private,
        encrypted_ecdh_private_nonce: fields.encrypted_ecdh_private_nonce,
        encrypted_signing_private: fields.encrypted_signing_private,
        encrypted_signing_private_nonce: fields.encrypted_signing_private_nonce,
        device_name: request.device_name,
        device_type: fields.device_type,
        device_ecdh_public_key: fields.device_ecdh_public_key,
        device_signing_public_key: fields.device_signing_public_key,
        device_client_nonce: fields.device_client_nonce,
        device_identity_signature: fields.device_identity_signature,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = RegisterResponse {
                id: result.user.id.to_string(),
                email: result.user.email.clone(),
                device_id: result.device.id.to_string(),
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            app_error_response!(e, AuthErrorResponse, conflict, bad_request)
        }
    }
}
