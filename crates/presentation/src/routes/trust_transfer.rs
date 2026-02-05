//! Trust Transfer routes
//!
//! Endpoints for secure trust state transfer between devices:
//! - POST /api/trust-transfer/nonce - Request transfer nonce (new device)
//! - POST /api/trust-transfer/state - Submit encrypted state (existing device)
//! - GET /api/trust-transfer/state - Retrieve encrypted state (new device)

use application::domain::document::{DocumentRepository, DocumentUpdateRepository};
use application::domain::encryption::{
    DeviceEncryptedUMKRepository, DeviceId, DeviceRepository, DocumentEncryptedKeyRepository,
    PendingDeviceRepository, UserEncryptedIdentityKeyRepository, UserEncryptedMasterKeyRepository,
    UserIdentityPublicKeyRepository, WorkspaceEncryptedKeyRepository,
};
use application::domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};
use application::domain::transfer_nonce::EncryptedTransferState;
use application::domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use application::identity::RegistrationService;
use application::trust_transfer::{
    RequestNonceCommand, RequestNonceHandler, RetrieveStateCommand, RetrieveStateHandler,
    SubmitStateCommand, SubmitStateHandler,
};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{AppState, AuthUserFull, auth::verify_pop};

/// Maximum size for encrypted state payload (1 MB)
const MAX_ENCRYPTED_STATE_SIZE: usize = 1024 * 1024;

/// Create trust transfer routes
pub fn routes<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    state: AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
) -> Router
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    Router::new()
        .route(
            "/nonce",
            post(request_nonce::<
                U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR,
            >),
        )
        .route(
            "/state",
            post(submit_state::<
                U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR,
            >),
        )
        .route(
            "/state",
            get(retrieve_state::<
                U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR,
            >),
        )
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

/// Request nonce error response
#[derive(Debug, Serialize, ToSchema)]
pub struct RequestNonceErrorResponse {
    pub error: String,
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
        (status = 404, description = "Device not found", body = RequestNonceErrorResponse),
        (status = 500, description = "Server error", body = RequestNonceErrorResponse),
    ),
    security(("session_cookie" = []))
)]
async fn request_nonce<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    auth: AuthUserFull<
        U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR,
    >,
    Json(req): Json<RequestNonceRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    let handler = RequestNonceHandler::new(
        state.transfer_nonce_store(),
        state.device_repo(),
        state.pending_device_repo(),
    );

    let command = RequestNonceCommand {
        user_id: auth.user.id,
        new_device_id: DeviceId::from_uuid(req.device_id),
    };

    match handler.handle(command).await {
        Ok(result) => {
            // Emit SSE event to notify existing devices
            state
                .device_event_bus()
                .trust_transfer_nonce_ready(
                    auth.user.id,
                    DeviceId::from_uuid(req.device_id),
                    &result.nonce,
                )
                .await;

            let response = RequestNonceResponse {
                nonce: base64_url::encode(&result.nonce),
                expires_at: result.expires_at.to_rfc3339(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) if e.is_not_found() => (
            StatusCode::NOT_FOUND,
            Json(RequestNonceErrorResponse {
                error: "Device not found".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to generate transfer nonce: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RequestNonceErrorResponse {
                    error: "Failed to generate nonce".to_string(),
                }),
            )
                .into_response()
        }
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

/// Submit state error response
#[derive(Debug, Serialize, ToSchema)]
pub struct SubmitStateErrorResponse {
    pub error: String,
    pub code: String,
}

impl SubmitStateErrorResponse {
    fn invalid_nonce() -> Self {
        Self {
            error: "Invalid or expired transfer nonce".to_string(),
            code: "invalid_nonce".to_string(),
        }
    }

    fn invalid_format(msg: &str) -> Self {
        Self {
            error: msg.to_string(),
            code: "invalid_format".to_string(),
        }
    }

    fn payload_too_large() -> Self {
        Self {
            error: "Encrypted state payload too large".to_string(),
            code: "payload_too_large".to_string(),
        }
    }

    fn target_device_not_found() -> Self {
        Self {
            error: "Target device not found".to_string(),
            code: "target_device_not_found".to_string(),
        }
    }

    fn server_error() -> Self {
        Self {
            error: "Server error".to_string(),
            code: "server_error".to_string(),
        }
    }
}

/// Submit encrypted trust state (existing device)
#[utoipa::path(
    post,
    path = "/api/trust-transfer/state",
    tag = "trust-transfer",
    request_body = SubmitStateRequest,
    responses(
        (status = 204, description = "State submitted successfully"),
        (status = 400, description = "Invalid request", body = SubmitStateErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Server error", body = SubmitStateErrorResponse),
    ),
    security(("session_cookie" = []))
)]
async fn submit_state<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    headers: HeaderMap,
    auth: AuthUserFull<
        U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR,
    >,
    Json(req): Json<SubmitStateRequest>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Verify PoP (Proof of Possession) - required for trust state transfer
    // Use the device_id from PopVerified to ensure sender_device_id matches the PoP-authenticated device
    let pop_verified = match verify_pop(
        &headers,
        auth.user.id,
        state.device_repo().as_ref(),
        &state.challenge_store(),
    )
    .await
    {
        Ok(verified) => verified,
        Err(e) => return e.into_response(),
    };

    // Use the device ID from PoP verification (not session) to ensure binding
    let sender_device_id = pop_verified.device.id;

    // Verify target device exists and belongs to this user
    let target_device_id = DeviceId::from_uuid(req.target_device_id);
    let device_repo = state.device_repo();

    // Check if target is a pending device or active device
    let pending_repo = state.pending_device_repo();
    let is_valid_target = match pending_repo.find_by_id(target_device_id).await {
        Ok(Some(pending)) => pending.user_id == auth.user.id,
        Ok(None) => {
            // Not a pending device, check active devices
            match device_repo.find_by_id(target_device_id).await {
                Ok(Some(device)) => device.user_id == auth.user.id && !device.is_revoked(),
                Ok(None) => false,
                Err(_) => false,
            }
        }
        Err(_) => false,
    };

    if !is_valid_target {
        return (
            StatusCode::BAD_REQUEST,
            Json(SubmitStateErrorResponse::target_device_not_found()),
        )
            .into_response();
    }

    // Decode transfer nonce
    let transfer_nonce: [u8; 32] = match base64_url::decode(&req.transfer_nonce) {
        Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitStateErrorResponse::invalid_format(
                    "transfer_nonce must be 32 bytes base64url",
                )),
            )
                .into_response();
        }
    };

    // Decode ciphertext
    let ciphertext = match base64_url::decode(&req.ciphertext) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitStateErrorResponse::invalid_format(
                    "Invalid ciphertext encoding",
                )),
            )
                .into_response();
        }
    };

    // Check payload size limit (on decoded bytes, not base64 string)
    if ciphertext.len() > MAX_ENCRYPTED_STATE_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(SubmitStateErrorResponse::payload_too_large()),
        )
            .into_response();
    }

    // Decode nonce
    let nonce: [u8; 24] = match base64_url::decode(&req.nonce) {
        Ok(bytes) if bytes.len() == 24 => bytes.try_into().unwrap(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitStateErrorResponse::invalid_format(
                    "nonce must be 24 bytes base64url",
                )),
            )
                .into_response();
        }
    };

    // Decode signature
    let signature: [u8; 64] = match base64_url::decode(&req.signature) {
        Ok(bytes) if bytes.len() == 64 => bytes.try_into().unwrap(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitStateErrorResponse::invalid_format(
                    "signature must be 64 bytes base64url",
                )),
            )
                .into_response();
        }
    };

    let handler = SubmitStateHandler::new(
        state.transfer_nonce_store(),
        state.transfer_state_store(),
    );

    let command = SubmitStateCommand {
        user_id: auth.user.id,
        sender_device_id,
        target_device_id: DeviceId::from_uuid(req.target_device_id),
        transfer_nonce,
        encrypted_state: EncryptedTransferState {
            ciphertext,
            nonce,
            signature,
            sender_device_id,
        },
    };

    match handler.handle(command).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) if e.is_bad_request() => (
            StatusCode::BAD_REQUEST,
            Json(SubmitStateErrorResponse::invalid_nonce()),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to submit transfer state: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SubmitStateErrorResponse::server_error()),
            )
                .into_response()
        }
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

/// Retrieve state error response
#[derive(Debug, Serialize, ToSchema)]
pub struct RetrieveStateErrorResponse {
    pub error: String,
    pub code: String,
}

impl RetrieveStateErrorResponse {
    fn not_found() -> Self {
        Self {
            error: "No transfer state available".to_string(),
            code: "not_found".to_string(),
        }
    }

    fn server_error() -> Self {
        Self {
            error: "Server error".to_string(),
            code: "server_error".to_string(),
        }
    }
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
        (status = 400, description = "Missing device_id", body = RetrieveStateErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "No state available", body = RetrieveStateErrorResponse),
        (status = 500, description = "Server error", body = RetrieveStateErrorResponse),
    ),
    security(("session_cookie" = []))
)]
async fn retrieve_state<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    auth: AuthUserFull<
        U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR,
    >,
    Query(query): Query<RetrieveStateQuery>,
) -> impl IntoResponse
where
    U: UserRepository + Send + Sync + Clone + 'static,
    S: SessionRepository + Send + Sync + Clone + 'static,
    US: UserSettingsRepository + Send + Sync + Clone + 'static,
    UIP: UserIdentityPublicKeyRepository + Send + Sync + Clone + 'static,
    UEM: UserEncryptedMasterKeyRepository + Send + Sync + Clone + 'static,
    UEI: UserEncryptedIdentityKeyRepository + Send + Sync + Clone + 'static,
    WR: WorkspaceRepository + Send + Sync + Clone + 'static,
    WMR: WorkspaceMemberRepository + Send + Sync + Clone + 'static,
    WRR: WorkspaceRoleRepository + Send + Sync + Clone + 'static,
    DR: DocumentRepository + Send + Sync + Clone + 'static,
    DUR: DocumentUpdateRepository + Send + Sync + Clone + 'static,
    WKR: WorkspaceEncryptedKeyRepository + Send + Sync + Clone + 'static,
    DKR: DocumentEncryptedKeyRepository + Send + Sync + Clone + 'static,
    RS: RegistrationService + Send + Sync + Clone + 'static,
    DER: DeviceRepository + Send + Sync + Clone + 'static,
    PDR: PendingDeviceRepository + Send + Sync + Clone + 'static,
    UMKR: DeviceEncryptedUMKRepository + Send + Sync + Clone + 'static,
{
    // Get device ID from query parameter (new device retrieving the state)
    let device_id = DeviceId::from_uuid(query.device_id);

    let handler = RetrieveStateHandler::new(state.transfer_state_store());

    let command = RetrieveStateCommand {
        user_id: auth.user.id,
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
        Err(e) if e.is_not_found() => (
            StatusCode::NOT_FOUND,
            Json(RetrieveStateErrorResponse::not_found()),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to retrieve transfer state: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RetrieveStateErrorResponse::server_error()),
            )
                .into_response()
        }
    }
}
