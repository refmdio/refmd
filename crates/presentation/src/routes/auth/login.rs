//! Login endpoint

use application::identity::{LoginPasswordUserCommand, LoginPasswordUserHandler};
use axum::{
    Json,
    extract::State,
    http::{StatusCode, header, HeaderMap},
    response::{AppendHeaders, IntoResponse},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AuthSubState;
use crate::routes::app_error_response;
use super::{AuthErrorResponse, build_session_cookie};

/// Login request
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    /// User email address
    #[schema(example = "user@example.com")]
    pub email: String,
    /// authKey for authentication (base64url encoded)
    #[schema(example = "base64url-encoded-auth-key")]
    pub auth_key: String,
    /// Remember me flag for extended session duration
    #[schema(example = false)]
    pub remember_me: bool,
    /// Device ID for session binding (optional, for existing devices)
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    #[serde(default)]
    pub device_id: Option<String>,
}

/// Login response
///
/// Session token is set via HttpOnly cookie, not in JSON body.
/// Note: Encrypted keys are only returned for verified (registered) devices.
/// New devices must go through the PendingDevice flow to receive keys.
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    /// Session expiration timestamp
    pub expires_at: String,
    /// User ID
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: String,
    /// User email
    #[schema(example = "user@example.com")]
    pub email: String,
    /// Whether user has any registered devices (for PoP enforcement)
    #[schema(example = true)]
    pub has_devices: bool,
    /// Whether the login device is verified (registered and active)
    #[schema(example = true)]
    pub device_verified: bool,
    /// Device ID if verified
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Encrypted keys (only present for verified devices)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<LoginResponseKeys>,
}

/// Encrypted keys returned only for verified devices
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponseKeys {
    /// Encrypted UMK (base64url encoded)
    #[schema(example = "base64url-encoded-encrypted-umk")]
    pub encrypted_umk: String,
    /// UMK nonce (base64url encoded)
    #[schema(example = "base64url-encoded-nonce")]
    pub umk_nonce: String,
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

/// Login with password authentication
///
/// Authenticates a user with email and authKey.
/// Session token is set via HttpOnly cookie (not in response body).
/// Client should derive authKey from password using Argon2id + HKDF.
#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful. Session cookie is set.", body = LoginResponse),
        (status = 400, description = "Invalid request", body = AuthErrorResponse),
        (status = 401, description = "Invalid credentials", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn login(
    State(state): State<AuthSubState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> impl IntoResponse {
    let handler = LoginPasswordUserHandler::new(
        state.user_repo.clone(),
        state.session_repo.clone(),
        state.user_encrypted_master_key_repo.clone(),
        state.user_encrypted_identity_key_repo.clone(),
        state.device_repo.clone(),
    );

    // Parse device_id if provided — return 400 on malformed UUID
    let device_id = match &request.device_id {
        Some(id) => match crate::crypto_validation::parse_device_id("device_id", id) {
            Ok(did) => Some(did),
            Err((status, msg)) => {
                return (status, Json(AuthErrorResponse { error: msg })).into_response();
            }
        },
        None => None,
    };

    // Extract client IP from proxy headers, fallback to socket address
    let socket_ip = connect_info.0.ip().to_string();
    let ip_address = Some(
        crate::client_ip::extract_client_ip(&headers)
            .unwrap_or(socket_ip)
            .chars()
            .take(45) // IPv6 max length
            .collect::<String>(),
    );

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect::<String>());

    let command = LoginPasswordUserCommand {
        email: request.email,
        auth_key: request.auth_key,
        remember_me: request.remember_me,
        ip_address,
        user_agent,
        device_id,
    };

    match handler.handle(command).await {
        Ok(result) => {
            // Build HttpOnly cookie
            let cookie = build_session_cookie(
                &result.session_token,
                result.expires_at,
                state.secure_cookies,
            );

            // Only include keys if device is verified
            let keys = result.keys.map(|k| LoginResponseKeys {
                encrypted_umk: base64_url::encode(&k.encrypted_umk),
                umk_nonce: base64_url::encode(&k.umk_nonce),
                encrypted_ecdh_private: base64_url::encode(&k.encrypted_ecdh_private),
                encrypted_ecdh_private_nonce: base64_url::encode(&k.encrypted_ecdh_private_nonce),
                encrypted_signing_private: base64_url::encode(&k.encrypted_signing_private),
                encrypted_signing_private_nonce: base64_url::encode(
                    &k.encrypted_signing_private_nonce,
                ),
            });

            let response = LoginResponse {
                expires_at: result.expires_at.to_rfc3339(),
                user_id: result.user.id.to_string(),
                email: result.user.email.clone(),
                has_devices: result.has_devices,
                device_verified: result.device_verified,
                device_id: result.device_id.map(|d| d.to_string()),
                keys,
            };

            (
                StatusCode::OK,
                AppendHeaders([(header::SET_COOKIE, cookie)]),
                Json(response),
            )
                .into_response()
        }
        Err(e) => {
            // Use safe_message() to prevent user enumeration
            app_error_response!(e, AuthErrorResponse, @safe, unauthorized, bad_request)
        }
    }
}
