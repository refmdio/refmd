//! PoP challenge endpoint

use application::identity::{CreatePopChallengeCommand, CreatePopChallengeHandler};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::AuthSubState;
use crate::auth::AuthUser;
use crate::auth::POP_DEVICE_ID_HEADER;
use crate::auth::pop::require_header;
use crate::routes::app_error_response;
use super::AuthErrorResponse;

/// PoP challenge response
#[derive(Debug, Serialize, ToSchema)]
pub struct PopChallengeResponse {
    /// Server-issued challenge (32 bytes, base64url encoded)
    #[schema(example = "base64url-encoded-challenge")]
    pub challenge: String,
    /// Challenge expiration timestamp (Unix timestamp)
    #[schema(example = 1738700000)]
    pub expires_at: i64,
}

/// Create a PoP challenge for device verification
///
/// Returns a server-issued challenge that the client must sign with
/// the device's Ed25519 signing key. The challenge is single-use and
/// expires after 5 minutes.
///
/// Requires:
/// - Valid session cookie
/// - X-PoP-Device-Id header with the device UUID
#[utoipa::path(
    post,
    path = "/api/auth/pop-challenge",
    responses(
        (status = 200, description = "Challenge created", body = PopChallengeResponse),
        (status = 400, description = "Missing or invalid device ID, or device revoked", body = AuthErrorResponse),
        (status = 401, description = "Not authenticated", body = AuthErrorResponse),
        (status = 404, description = "Device not found", body = AuthErrorResponse),
        (status = 500, description = "Internal server error", body = AuthErrorResponse),
    ),
    tag = "auth"
)]
pub async fn create_pop_challenge(
    auth_user: AuthUser,
    State(state): State<AuthSubState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Extract device ID from header — return 400 (not 401) for missing/invalid header
    // because this is a validation error, not an authentication failure.
    let device_id_str = match require_header(&headers, POP_DEVICE_ID_HEADER) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse {
                    error: format!("missing or invalid {} header", POP_DEVICE_ID_HEADER),
                }),
            )
                .into_response();
        }
    };

    let device_id = match crate::crypto_validation::parse_device_id("device_id", device_id_str) {
        Ok(did) => did,
        Err((status, msg)) => {
            return (status, Json(AuthErrorResponse { error: msg })).into_response();
        }
    };

    // Use application layer handler for device validation and challenge generation
    let handler = CreatePopChallengeHandler::new(
        state.device_repo.clone(),
        state.challenge_store.clone(),
    );

    let command = CreatePopChallengeCommand {
        user_id: auth_user.user_id,
        device_id,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = PopChallengeResponse {
                challenge: base64_url::encode(&result.challenge),
                expires_at: result.expires_at.timestamp(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            app_error_response!(e, AuthErrorResponse, not_found, bad_request)
        }
    }
}
