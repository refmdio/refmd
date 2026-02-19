//! Trust Transfer routes
//!
//! Endpoints for secure trust state transfer between devices:
//! - POST /api/trust-transfer/nonce - Request transfer nonce (new device)
//! - POST /api/trust-transfer/state - Submit encrypted state (existing device)
//! - GET /api/trust-transfer/state - Retrieve encrypted state (new device)

use crate::map_decode_response;
use application::types::{DeviceId, EncryptedTransferStateDto};
use application::trust_transfer::{
    RequestNonceCommand, RequestNonceHandler, RetrieveStateCommand, RetrieveStateHandler,
    SubmitStateCommand, SubmitStateHandler,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{AppState, AuthUser, PopVerifiedUser, TrustTransferSubState};
use crate::crypto_validation::{decode_b64_array, decode_b64_max};
use super::{app_error_response, error_response_struct};

/// Maximum encrypted trust state payload (1 MB, matches application layer limit).
const MAX_ENCRYPTED_STATE_BYTES: usize = 1024 * 1024;

// Shared error response type for all trust-transfer endpoints
error_response_struct!(TrustTransferErrorResponse);

/// Trust transfer routes requiring PoP verification (behind PopLayer)
pub fn pop_routes(state: AppState) -> Router {
    Router::new()
        .route("/state", post(submit_state))
        .with_state(state)
}

/// Trust transfer routes requiring session auth only (no PoP)
pub fn session_routes(state: AppState) -> Router {
    Router::new()
        .route("/nonce", post(request_nonce))
        .route("/state", get(retrieve_state))
        .with_state(state)
}

// ============================================================================
// Request Transfer Nonce
// ============================================================================

/// Request nonce request body
#[derive(Debug, Deserialize, ToSchema)]
pub struct RequestNonceRequest {
    /// Device ID of the new device requesting the transfer
    pub device_id: Uuid,
}

/// Request nonce response
#[derive(Debug, Serialize, ToSchema)]
pub struct RequestNonceResponse {
    /// Transfer nonce (base64url encoded, 32 bytes)
    pub nonce: String,
    /// Expiration timestamp (ISO 8601)
    pub expires_at: String,
}

/// Request a transfer nonce (new device)
#[utoipa::path(
    post,
    path = "/api/trust-transfer/nonce",
    tag = "trust-transfer",
    request_body = RequestNonceRequest,
    responses(
        (status = 200, description = "Nonce generated", body = RequestNonceResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Device not found", body = TrustTransferErrorResponse),
        (status = 500, description = "Server error", body = TrustTransferErrorResponse),
    ),
    security(("session_cookie" = []))
)]
async fn request_nonce(
    State(state): State<TrustTransferSubState>,
    auth: AuthUser,
    Json(req): Json<RequestNonceRequest>,
) -> impl IntoResponse {
    let handler = RequestNonceHandler::new(
        state.transfer_nonce_store.clone(),
        state.device_repo.clone(),
        state.pending_device_repo.clone(),
        state.device_event_bus.clone(),
    );

    let command = RequestNonceCommand {
        user_id: auth.user_id,
        new_device_id: DeviceId::from_uuid(req.device_id),
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = RequestNonceResponse {
                nonce: base64_url::encode(&result.nonce),
                expires_at: result.expires_at.to_rfc3339(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, TrustTransferErrorResponse, not_found),
    }
}

// ============================================================================
// Submit Encrypted State
// ============================================================================

/// Submit state request body
#[derive(Debug, Deserialize, ToSchema)]
pub struct SubmitStateRequest {
    /// Target device ID (the new device)
    pub target_device_id: Uuid,
    /// Transfer nonce (base64url encoded, 32 bytes)
    pub transfer_nonce: String,
    /// Encrypted trust state ciphertext (base64url encoded)
    pub ciphertext: String,
    /// XChaCha20-Poly1305 nonce (base64url encoded, 24 bytes)
    pub nonce: String,
    /// Ed25519 signature (base64url encoded, 64 bytes)
    pub signature: String,
}

/// Decoded binary fields from a submit-state request.
struct DecodedSubmitFields {
    transfer_nonce: [u8; 32],
    ciphertext: Vec<u8>,
    nonce: [u8; 24],
    signature: [u8; 64],
}

/// Decode and validate all base64url-encoded fields from a submit-state request.
#[allow(clippy::result_large_err)]
fn decode_submit_fields(
    req: &SubmitStateRequest,
) -> Result<DecodedSubmitFields, Response> {
    let transfer_nonce: [u8; 32] =
        decode_b64_array("transfer_nonce", &req.transfer_nonce).map_err(map_decode_response!(TrustTransferErrorResponse))?;
    let ciphertext = decode_b64_max("ciphertext", &req.ciphertext, MAX_ENCRYPTED_STATE_BYTES).map_err(map_decode_response!(TrustTransferErrorResponse))?;
    let nonce: [u8; 24] = decode_b64_array("nonce", &req.nonce).map_err(map_decode_response!(TrustTransferErrorResponse))?;
    let signature: [u8; 64] = decode_b64_array("signature", &req.signature).map_err(map_decode_response!(TrustTransferErrorResponse))?;

    Ok(DecodedSubmitFields { transfer_nonce, ciphertext, nonce, signature })
}

/// Submit encrypted trust state (existing device)
#[utoipa::path(
    post,
    path = "/api/trust-transfer/state",
    tag = "trust-transfer",
    request_body = SubmitStateRequest,
    responses(
        (status = 204, description = "State submitted successfully"),
        (status = 400, description = "Invalid request", body = TrustTransferErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 413, description = "Payload too large", body = TrustTransferErrorResponse),
        (status = 500, description = "Server error", body = TrustTransferErrorResponse),
    ),
    security(("session_cookie" = []))
)]
async fn submit_state(
    State(state): State<TrustTransferSubState>,
    pop_user: PopVerifiedUser,
    Json(req): Json<SubmitStateRequest>,
) -> impl IntoResponse {
    // Use the device ID from PoP verification (not session) to ensure binding
    let sender_device_id = pop_user.device.id;

    // Decode and validate all binary fields
    let fields = match decode_submit_fields(&req) {
        Ok(fields) => fields,
        Err(resp) => return resp,
    };

    let handler = SubmitStateHandler::new(
        state.transfer_nonce_store.clone(),
        state.transfer_state_store.clone(),
        state.device_repo.clone(),
        state.pending_device_repo.clone(),
    );

    let command = SubmitStateCommand {
        user_id: pop_user.user_id,
        sender_device_id,
        target_device_id: DeviceId::from_uuid(req.target_device_id),
        transfer_nonce: fields.transfer_nonce,
        encrypted_state: EncryptedTransferStateDto {
            ciphertext: fields.ciphertext,
            nonce: fields.nonce,
            signature: fields.signature,
            sender_device_id,
        },
    };

    match handler.handle(command).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(application::trust_transfer::SubmitStateError::PayloadTooLarge) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(TrustTransferErrorResponse {
                error: "encrypted state payload too large".to_string(),
            }),
        )
            .into_response(),
        Err(e) => app_error_response!(e, TrustTransferErrorResponse, bad_request),
    }
}

// ============================================================================
// Retrieve Encrypted State
// ============================================================================

/// Retrieve state response
#[derive(Debug, Serialize, ToSchema)]
pub struct RetrieveStateResponse {
    /// Sender device ID
    pub sender_device_id: Uuid,
    /// Encrypted trust state ciphertext (base64url encoded)
    pub ciphertext: String,
    /// XChaCha20-Poly1305 nonce (base64url encoded, 24 bytes)
    pub nonce: String,
    /// Ed25519 signature (base64url encoded, 64 bytes)
    pub signature: String,
}

/// Query parameters for retrieve state
#[derive(Debug, Deserialize, ToSchema)]
pub struct RetrieveStateQuery {
    /// Device ID of the new device requesting the state
    #[schema(example = "01234567-89ab-cdef-0123-456789abcdef")]
    pub device_id: Uuid,
}

/// Retrieve encrypted trust state (new device)
#[utoipa::path(
    get,
    path = "/api/trust-transfer/state",
    tag = "trust-transfer",
    params(
        ("device_id" = Uuid, Query, description = "Device ID of the new device")
    ),
    responses(
        (status = 200, description = "State retrieved", body = RetrieveStateResponse),
        (status = 400, description = "Missing device_id", body = TrustTransferErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "No state available", body = TrustTransferErrorResponse),
        (status = 500, description = "Server error", body = TrustTransferErrorResponse),
    ),
    security(("session_cookie" = []))
)]
async fn retrieve_state(
    State(state): State<TrustTransferSubState>,
    auth: AuthUser,
    Query(query): Query<RetrieveStateQuery>,
) -> impl IntoResponse {
    // Get device ID from query parameter (new device retrieving the state)
    let device_id = DeviceId::from_uuid(query.device_id);

    let handler = RetrieveStateHandler::new(state.transfer_state_store.clone());

    let command = RetrieveStateCommand {
        user_id: auth.user_id,
        device_id,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = RetrieveStateResponse {
                sender_device_id: result.encrypted_state.sender_device_id.as_uuid(),
                ciphertext: base64_url::encode(&result.encrypted_state.ciphertext),
                nonce: base64_url::encode(&result.encrypted_state.nonce),
                signature: base64_url::encode(&result.encrypted_state.signature),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, TrustTransferErrorResponse, not_found),
    }
}
