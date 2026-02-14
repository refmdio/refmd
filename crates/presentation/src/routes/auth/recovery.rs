//! Recovery endpoints

use application::identity::{
    CreateRecoveryChallengeCommand, CreateRecoveryChallengeHandler, GetRecoveryDataHandler,
    GetRecoveryDataQuery, RecoverySessionCommand, RecoverySessionHandler,
};
use axum::{
    Json,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{AppendHeaders, IntoResponse},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AuthSubState;
use crate::crypto_validation::{decode_b64_exact, decode_signature};
use crate::routes::app_error_response;
use crate::try_decode;
use super::{AuthErrorResponse, build_session_cookie};

/// Get recovery data query parameters (HTTP)
#[derive(Debug, Deserialize, ToSchema)]
pub struct GetRecoveryQueryParams {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
}

/// Get recovery data response
#[derive(Debug, Serialize, ToSchema)]
pub struct GetRecoveryResponse {
    /// User ID (needed for AAD verification)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: String,
    /// Recovery encrypted UMK (base64url encoded)
    #[schema(example = "base64url-encoded-recovery-encrypted-umk")]
    pub recovery_encrypted_umk: String,
    /// Recovery nonce (base64url encoded)
    #[schema(example = "base64url-encoded-recovery-nonce")]
    pub recovery_nonce: String,
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
}

/// Recovery challenge request
#[derive(Debug, Deserialize, ToSchema)]
pub struct RecoveryChallengeRequest {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
}

/// Recovery challenge response
#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryChallengeResponse {
    /// Server-issued challenge (32 bytes, base64url encoded)
    #[schema(example = "base64url-encoded-challenge")]
    pub challenge: String,
    /// Challenge expiration timestamp (Unix timestamp)
    #[schema(example = 1738700000)]
    pub expires_at: i64,
}

/// Recovery session request
#[derive(Debug, Deserialize, ToSchema)]
pub struct RecoverySessionRequest {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Server-issued challenge (base64url encoded, 32 bytes)
    #[schema(example = "base64url-encoded-challenge")]
    pub challenge: String,
    /// Ed25519 signature of recovery session message (base64url encoded, 64 bytes)
    #[schema(example = "base64url-encoded-signature")]
    pub identity_signature: String,
    /// Unix timestamp (seconds) included in signed message
    #[schema(example = 1738700000)]
    pub timestamp: i64,
}

/// Recovery session response
#[derive(Debug, Serialize, ToSchema)]
pub struct RecoverySessionResponse {
    /// User ID
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: String,
    /// User email
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Session expiration timestamp (ISO 8601)
    pub expires_at: String,
    /// Whether user has any registered devices
    #[schema(example = true)]
    pub has_devices: bool,
}

/// Get recovery data for account recovery
///
/// Returns encrypted UMK (encrypted with recovery key) and encrypted identity keys.
/// Client will decrypt UMK using the recovery key derived from 24-word mnemonic,
/// then use UMK to decrypt identity keys.
#[utoipa::path(
    get,
    path = "/api/auth/recovery",
    params(
        ("email" = String, Query, description = "User email address")
    ),
    responses(
        (status = 200, description = "Recovery data (returns plausible dummy data for non-existent users to prevent enumeration)", body = GetRecoveryResponse),
        (status = 400, description = "Invalid email", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn get_recovery(
    State(state): State<AuthSubState>,
    Query(params): Query<GetRecoveryQueryParams>,
) -> impl IntoResponse {
    let handler = GetRecoveryDataHandler::new(
        state.user_repo.clone(),
        state.user_encrypted_master_key_repo.clone(),
        state.user_encrypted_identity_key_repo.clone(),
        state.server_secret.clone(),
    );

    let query = GetRecoveryDataQuery {
        email: params.email,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let response = GetRecoveryResponse {
                user_id: result.user_id.to_string(),
                recovery_encrypted_umk: base64_url::encode(&result.recovery_encrypted_umk),
                recovery_nonce: base64_url::encode(&result.recovery_nonce),
                encrypted_ecdh_private: base64_url::encode(&result.encrypted_ecdh_private),
                encrypted_ecdh_private_nonce: base64_url::encode(
                    &result.encrypted_ecdh_private_nonce,
                ),
                encrypted_signing_private: base64_url::encode(&result.encrypted_signing_private),
                encrypted_signing_private_nonce: base64_url::encode(
                    &result.encrypted_signing_private_nonce,
                ),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            app_error_response!(e, AuthErrorResponse, bad_request)
        }
    }
}

/// Create a recovery challenge for account recovery
///
/// Returns a server-issued challenge that must be signed with the user's
/// Identity signing key. The challenge is single-use and expires after 5 minutes.
///
/// For user enumeration prevention, always returns a challenge even for
/// non-existent users (the challenge just won't be usable).
#[utoipa::path(
    post,
    path = "/api/auth/recovery/challenge",
    request_body = RecoveryChallengeRequest,
    responses(
        (status = 200, description = "Challenge created", body = RecoveryChallengeResponse),
        (status = 400, description = "Invalid email", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn create_recovery_challenge(
    State(state): State<AuthSubState>,
    Json(request): Json<RecoveryChallengeRequest>,
) -> impl IntoResponse {
    let handler = CreateRecoveryChallengeHandler::new(state.recovery_challenge_store.clone());

    let command = CreateRecoveryChallengeCommand {
        email: request.email,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = RecoveryChallengeResponse {
                challenge: base64_url::encode(&result.challenge),
                expires_at: result.expires_at.timestamp(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            app_error_response!(e, AuthErrorResponse, bad_request)
        }
    }
}

/// Create a recovery session using Identity signature
///
/// Authenticates the user by verifying their Identity key signature
/// over the server-issued challenge. No password required.
///
/// The client must sign: "recovery-session:" || challenge(32) || email || timestamp(8, LE)
#[utoipa::path(
    post,
    path = "/api/auth/recovery/session",
    request_body = RecoverySessionRequest,
    responses(
        (status = 200, description = "Session created. Session cookie is set.", body = RecoverySessionResponse),
        (status = 400, description = "Invalid request", body = AuthErrorResponse),
        (status = 401, description = "Invalid signature or challenge", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn create_recovery_session(
    State(state): State<AuthSubState>,
    Json(request): Json<RecoverySessionRequest>,
) -> impl IntoResponse {
    // Decode base64url fields using shared validation helpers
    let challenge = try_decode!(decode_b64_exact("challenge", &request.challenge, 32), AuthErrorResponse);
    let identity_signature = try_decode!(decode_signature("identity_signature", &request.identity_signature), AuthErrorResponse);

    // Normalize email (must match challenge creation)
    let email = request.email.trim().to_lowercase();

    // Use the application layer handler
    let handler = RecoverySessionHandler::new(
        state.user_repo.clone(),
        state.session_repo.clone(),
        state.user_identity_public_key_repo.clone(),
        state.device_repo.clone(),
        state.recovery_challenge_store.clone(),
    );

    let command = RecoverySessionCommand {
        email,
        challenge,
        identity_signature,
        timestamp: request.timestamp,
    };

    match handler.handle(command).await {
        Ok(result) => {
            // Build HttpOnly cookie
            let cookie = build_session_cookie(
                &result.session_token,
                result.expires_at,
                state.secure_cookies,
            );

            let response = RecoverySessionResponse {
                user_id: result.user.id.to_string(),
                email: result.user.email.clone(),
                expires_at: result.expires_at.to_rfc3339(),
                has_devices: result.has_devices,
            };

            (
                StatusCode::OK,
                AppendHeaders([(header::SET_COOKIE, cookie)]),
                Json(response),
            )
                .into_response()
        }
        Err(e) => {
            app_error_response!(e, AuthErrorResponse, @safe, bad_request, unauthorized)
        }
    }
}
