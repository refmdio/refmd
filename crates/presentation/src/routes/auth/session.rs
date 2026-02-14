//! Session endpoints (logout, me)

use application::identity::{
    GetCurrentUserHandler, GetCurrentUserQuery, LogoutSessionCommand, LogoutSessionHandler,
};
use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{AppendHeaders, IntoResponse},
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::AuthSubState;
use super::super::app_error_response;
use super::{AuthErrorResponse, build_clear_cookie};

/// Logout response
#[derive(Debug, Serialize, ToSchema)]
pub struct LogoutResponse {
    /// Success message
    #[schema(example = "logged out")]
    pub message: String,
}

/// Current user response (for session restoration)
#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    /// User ID
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub user_id: String,
    /// User email
    #[schema(example = "user@example.com")]
    pub email: String,
    /// User display name
    #[schema(example = "John Doe")]
    pub name: String,
    /// Authentication type ("password" or "oauth")
    #[schema(example = "password")]
    pub auth_type: String,
    /// Session expiration timestamp
    pub expires_at: String,
    /// Whether user has any registered devices (for PoP enforcement)
    #[schema(example = true)]
    pub has_devices: bool,
    /// Whether the session device is verified (registered and active)
    #[schema(example = true)]
    pub device_verified: bool,
    /// Device ID if verified
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Encrypted keys (only present for verified devices)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<MeResponseKeys>,
}

/// Encrypted keys returned only for verified devices in /me response
#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponseKeys {
    /// Encrypted UMK (base64url encoded, omitted for OAuth users)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "base64url-encoded-encrypted-umk")]
    pub encrypted_umk: Option<String>,
    /// UMK nonce (base64url encoded, omitted for OAuth users)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "base64url-encoded-nonce")]
    pub umk_nonce: Option<String>,
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

/// Logout and clear session
///
/// Clears the session cookie and server-side session.
/// Normal logout preserves IndexedDB (DSK, device keys) for session restore.
/// For full local data clearing, use secure logout on the client side.
#[utoipa::path(
    post,
    path = "/api/auth/logout",
    responses(
        (status = 200, description = "Logout successful", body = LogoutResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn logout(
    State(state): State<AuthSubState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Clear cookie regardless of server-side outcome
    let clear_cookie = build_clear_cookie(state.secure_cookies);
    let cookie_header = AppendHeaders([(header::SET_COOKIE, clear_cookie)]);

    // Invalidate session on server if cookie exists
    if let Ok(token) = crate::auth::extract_session_token(&headers) {
        let token_hash = crate::auth::hash_session_token(token);
        let handler = LogoutSessionHandler::new(state.session_repo.clone());
        if let Err(e) = handler.handle(LogoutSessionCommand { token_hash }).await {
            return (
                cookie_header,
                app_error_response!(e, AuthErrorResponse),
            )
                .into_response();
        }
    }

    (
        StatusCode::OK,
        cookie_header,
        Json(LogoutResponse {
            message: "logged out".to_string(),
        }),
    )
        .into_response()
}

/// Get current user info and encrypted keys
///
/// Returns user info and encrypted keys for session restoration.
/// Requires valid session cookie. Used when client has DSK cached but needs encrypted keys.
#[utoipa::path(
    get,
    path = "/api/auth/me",
    responses(
        (status = 200, description = "Current user info", body = MeResponse),
        (status = 401, description = "Not authenticated", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn me(
    State(state): State<AuthSubState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Extract session token from cookie
    let token = match crate::auth::extract_session_token(&headers) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(AuthErrorResponse { error: e.error }),
            )
                .into_response();
        }
    };

    // Hash the token
    let token_hash = crate::auth::hash_session_token(token);

    // Use application layer handler
    let handler = GetCurrentUserHandler::new(
        state.user_repo.clone(),
        state.session_repo.clone(),
        state.user_encrypted_master_key_repo.clone(),
        state.user_encrypted_identity_key_repo.clone(),
        state.device_repo.clone(),
    );

    let query = GetCurrentUserQuery { token_hash };

    let result = match handler.handle(query).await {
        Ok(r) => r,
        Err(e) => {
            return app_error_response!(e, AuthErrorResponse, unauthorized);
        }
    };

    let keys = result.keys.map(|k| MeResponseKeys {
        encrypted_umk: k.encrypted_umk.map(|v| base64_url::encode(&v)),
        umk_nonce: k.umk_nonce.map(|v| base64_url::encode(&v)),
        encrypted_ecdh_private: base64_url::encode(&k.encrypted_ecdh_private),
        encrypted_ecdh_private_nonce: base64_url::encode(&k.encrypted_ecdh_private_nonce),
        encrypted_signing_private: base64_url::encode(&k.encrypted_signing_private),
        encrypted_signing_private_nonce: base64_url::encode(&k.encrypted_signing_private_nonce),
    });

    let response = MeResponse {
        user_id: result.user.id.to_string(),
        email: result.user.email.clone(),
        name: result.user.name,
        auth_type: result.auth_type,
        expires_at: result.session.expires_at.to_rfc3339(),
        has_devices: result.has_devices,
        device_verified: result.device_verified,
        device_id: result.device_id.map(|d| d.to_string()),
        keys,
    };

    (StatusCode::OK, Json(response)).into_response()
}
