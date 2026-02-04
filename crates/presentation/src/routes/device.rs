//! Device management routes
//!
//! Endpoints for multi-device support:
//! - Create pending device
//! - Get SAS for verification
//! - Approve device (promote from pending)
//! - List devices
//! - Revoke device
//! - Distribute UMK to device

use application::domain::document::{DocumentRepository, DocumentUpdateRepository};
use application::domain::encryption::{
    DeviceEncryptedUMKRepository, DeviceId, DeviceRepository, DeviceType,
    DocumentEncryptedKeyRepository, PendingDeviceRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository,
    WorkspaceEncryptedKeyRepository,
};
use application::domain::identity::{SessionRepository, UserRepository, UserSettingsRepository};
use application::domain::workspace::{
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use application::encryption::{
    ApproveDeviceCommand, ApproveDeviceHandler, CreatePendingDeviceCommand,
    CreatePendingDeviceHandler, DistributeUmkCommand, DistributeUmkHandler, GetSasHandler,
    GetSasQuery,
};
use application::identity::RegistrationService;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use tower_governor::GovernorLayer;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{AppState, AuthUserFull, rate_limit::create_device_rate_limit_config};

/// Create device routes
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
    // Rate limiting config for device registration
    let device_rate_limit = create_device_rate_limit_config();

    // Rate-limited routes (device registration)
    let rate_limited_routes = Router::new()
        .route(
            "/pending",
            post(create_pending_device::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>),
        )
        .layer(GovernorLayer {
            config: device_rate_limit,
        });

    // Non-rate-limited routes (authenticated endpoints)
    let other_routes = Router::new()
        .route(
            "/pending/{id}/sas",
            get(get_sas::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>),
        )
        .route(
            "/pending/{id}/approve",
            post(approve_device::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>),
        )
        .route(
            "/",
            get(list_devices::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>),
        )
        .route(
            "/{id}",
            delete(revoke_device::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>),
        )
        .route(
            "/{id}/keys/umk",
            post(distribute_umk::<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>),
        );

    Router::new()
        .merge(rate_limited_routes)
        .merge(other_routes)
        .with_state(state)
}

/// Error response
#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceErrorResponse {
    pub error: String,
}

/// Create pending device request
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePendingDeviceRequest {
    /// Device name
    #[schema(example = "My MacBook Pro")]
    pub device_name: String,
    /// Device type: "browser", "desktop", or "mobile"
    #[schema(example = "desktop")]
    pub device_type: String,
    /// X25519 ECDH public key (base64url, 32 bytes)
    #[schema(example = "base64url-encoded-ecdh-public-key")]
    pub ecdh_public_key: String,
    /// Ed25519 signing public key (base64url, 32 bytes)
    #[schema(example = "base64url-encoded-signing-public-key")]
    pub signing_public_key: String,
    /// Client nonce for SAS (base64url, 16 bytes)
    #[schema(example = "base64url-encoded-nonce")]
    pub client_nonce: String,
}

/// Create pending device response
#[derive(Debug, Serialize, ToSchema)]
pub struct CreatePendingDeviceResponse {
    /// Pending device ID
    pub id: String,
    /// Expiration time
    pub expires_at: String,
    /// User's identity signing public key (base64url, 32 bytes) for SAS calculation
    pub identity_signing_public_key: String,
}

/// Create a new pending device
#[utoipa::path(
    post,
    path = "/api/devices/pending",
    request_body = CreatePendingDeviceRequest,
    responses(
        (status = 201, description = "Pending device created", body = CreatePendingDeviceResponse),
        (status = 400, description = "Invalid request", body = DeviceErrorResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
pub async fn create_pending_device<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    auth_user: AuthUserFull<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    Json(request): Json<CreatePendingDeviceRequest>,
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
    // Parse device type
    let device_type: DeviceType = match request.device_type.parse() {
        Ok(dt) => dt,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid device_type: must be 'browser', 'desktop', or 'mobile'"
                        .to_string(),
                }),
            )
                .into_response();
        }
    };

    // Decode base64url fields
    let ecdh_public_key = match base64_url::decode(&request.ecdh_public_key) {
        Ok(k) if k.len() == 32 => k,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid ecdh_public_key: must be 32 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid ecdh_public_key encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let signing_public_key = match base64_url::decode(&request.signing_public_key) {
        Ok(k) if k.len() == 32 => k,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid signing_public_key: must be 32 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid signing_public_key encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let client_nonce = match base64_url::decode(&request.client_nonce) {
        Ok(n) if n.len() == 16 => n,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid client_nonce: must be 16 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid client_nonce encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let handler = CreatePendingDeviceHandler::new(
        state.pending_device_repo(),
        state.user_identity_public_key_repo(),
    );

    let command = CreatePendingDeviceCommand {
        user_id: auth_user.user.id,
        device_name: request.device_name,
        device_type,
        ecdh_public_key,
        signing_public_key,
        client_nonce,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = CreatePendingDeviceResponse {
                id: result.pending_device.id.to_string(),
                expires_at: result.pending_device.expires_at.to_rfc3339(),
                identity_signing_public_key: base64_url::encode(&result.identity_signing_public_key),
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            let status = if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(DeviceErrorResponse { error: e.to_string() })).into_response()
        }
    }
}

/// Get SAS response
///
/// For MITM detection, clients MUST calculate SAS locally using
/// `device_signing_public_key`, `device_ecdh_public_key`, `client_nonce`
/// and their LOCAL identity signing public key.
/// The `sas_indices` field is deprecated and kept only for backwards compatibility.
#[derive(Debug, Serialize, ToSchema)]
pub struct GetSasResponse {
    /// SAS emoji indices (7 values, 0-255 each)
    /// DEPRECATED: Use client-side calculation instead for MITM protection
    #[deprecated = "Use client-side SAS calculation for MITM protection"]
    pub sas_indices: Vec<u8>,
    /// Device name
    pub device_name: String,
    /// Device type
    pub device_type: String,
    /// Expiration time
    pub expires_at: String,
    /// New device's signing public key (base64url, 32 bytes) - for client-side SAS calculation
    pub device_signing_public_key: String,
    /// New device's ECDH public key (base64url, 32 bytes) - for client-side SAS calculation
    pub device_ecdh_public_key: String,
    /// Client nonce (base64url, 16 bytes) - for client-side SAS calculation
    pub client_nonce: String,
}

/// Get SAS for pending device verification
#[utoipa::path(
    get,
    path = "/api/devices/pending/{id}/sas",
    params(
        ("id" = Uuid, Path, description = "Pending device ID")
    ),
    responses(
        (status = 200, description = "SAS data", body = GetSasResponse),
        (status = 400, description = "Device expired", body = DeviceErrorResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
        (status = 403, description = "Not owner", body = DeviceErrorResponse),
        (status = 404, description = "Device not found", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
pub async fn get_sas<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    auth_user: AuthUserFull<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    Path(id): Path<Uuid>,
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
    let handler = GetSasHandler::new(
        state.pending_device_repo(),
        state.user_identity_public_key_repo(),
    );

    let query = GetSasQuery {
        pending_device_id: DeviceId::from_uuid(id),
        user_id: auth_user.user.id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let response = GetSasResponse {
                sas_indices: result.sas_indices,
                device_name: result.device_name,
                device_type: result.device_type,
                expires_at: result.expires_at.to_rfc3339(),
                device_signing_public_key: base64_url::encode(&result.device_signing_public_key),
                device_ecdh_public_key: base64_url::encode(&result.device_ecdh_public_key),
                client_nonce: base64_url::encode(&result.client_nonce),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(DeviceErrorResponse { error: e.to_string() })).into_response()
        }
    }
}

/// Approve device request
#[derive(Debug, Deserialize, ToSchema)]
pub struct ApproveDeviceRequest {
    /// Identity signature from existing device (base64url, 64 bytes)
    #[schema(example = "base64url-encoded-signature")]
    pub identity_signature: String,
}

/// Approve device response
#[derive(Debug, Serialize, ToSchema)]
pub struct ApproveDeviceResponse {
    /// Approved device ID
    pub id: String,
    /// Device name
    pub device_name: String,
    /// Device type
    pub device_type: String,
    /// Created timestamp
    pub created_at: String,
}

/// Approve a pending device after SAS verification
#[utoipa::path(
    post,
    path = "/api/devices/pending/{id}/approve",
    params(
        ("id" = Uuid, Path, description = "Pending device ID")
    ),
    request_body = ApproveDeviceRequest,
    responses(
        (status = 200, description = "Device approved", body = ApproveDeviceResponse),
        (status = 400, description = "Device expired or invalid signature", body = DeviceErrorResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
        (status = 403, description = "Not owner", body = DeviceErrorResponse),
        (status = 404, description = "Device not found", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
pub async fn approve_device<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    auth_user: AuthUserFull<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    Path(id): Path<Uuid>,
    Json(request): Json<ApproveDeviceRequest>,
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
    // Decode identity signature
    let identity_signature = match base64_url::decode(&request.identity_signature) {
        Ok(s) if s.len() == 64 => s,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid identity_signature: must be 64 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid identity_signature encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let handler = ApproveDeviceHandler::new(
        state.device_repo(),
        state.pending_device_repo(),
        state.user_identity_public_key_repo(),
    );

    let command = ApproveDeviceCommand {
        pending_device_id: DeviceId::from_uuid(id),
        user_id: auth_user.user.id,
        identity_signature,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = ApproveDeviceResponse {
                id: result.device.id.to_string(),
                device_name: result.device.name,
                device_type: result.device.device_type.as_str().to_string(),
                created_at: result.device.created_at.to_rfc3339(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(DeviceErrorResponse { error: e.to_string() })).into_response()
        }
    }
}

/// Device response
#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceResponse {
    pub id: String,
    pub name: String,
    pub device_type: String,
    pub last_seen_at: String,
    pub created_at: String,
    pub is_current: bool,
}

/// List devices response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListDevicesResponse {
    pub devices: Vec<DeviceResponse>,
}

/// List all devices for the current user
#[utoipa::path(
    get,
    path = "/api/devices",
    responses(
        (status = 200, description = "List of devices", body = ListDevicesResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
pub async fn list_devices<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    auth_user: AuthUserFull<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
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
    let device_repo = state.device_repo();

    match device_repo.find_active_by_user_id(auth_user.user.id).await {
        Ok(devices) => {
            let response = ListDevicesResponse {
                devices: devices
                    .into_iter()
                    .map(|d| DeviceResponse {
                        id: d.id.to_string(),
                        name: d.name,
                        device_type: d.device_type.as_str().to_string(),
                        last_seen_at: d.last_seen_at.to_rfc3339(),
                        created_at: d.created_at.to_rfc3339(),
                        is_current: false, // TODO: Compare with current session's device
                    })
                    .collect(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(DeviceErrorResponse {
                error: format!("failed to list devices: {}", e),
            }),
        )
            .into_response(),
    }
}

/// Revoke device response
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokeDeviceResponse {
    pub message: String,
}

/// Revoke (deauthorize) a device
#[utoipa::path(
    delete,
    path = "/api/devices/{id}",
    params(
        ("id" = Uuid, Path, description = "Device ID")
    ),
    responses(
        (status = 200, description = "Device revoked", body = RevokeDeviceResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
        (status = 403, description = "Not owner", body = DeviceErrorResponse),
        (status = 404, description = "Device not found", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
pub async fn revoke_device<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    auth_user: AuthUserFull<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    Path(id): Path<Uuid>,
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
    let device_repo = state.device_repo();
    let device_id = DeviceId::from_uuid(id);

    // Find device
    let mut device = match device_repo.find_by_id(device_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(DeviceErrorResponse {
                    error: "device not found".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(DeviceErrorResponse {
                    error: format!("failed to find device: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Verify ownership
    if device.user_id != auth_user.user.id {
        return (
            StatusCode::FORBIDDEN,
            Json(DeviceErrorResponse {
                error: "device does not belong to this user".to_string(),
            }),
        )
            .into_response();
    }

    // Revoke device
    device.revoke();

    match device_repo.save(&device).await {
        Ok(()) => (
            StatusCode::OK,
            Json(RevokeDeviceResponse {
                message: "device revoked".to_string(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(DeviceErrorResponse {
                error: format!("failed to revoke device: {}", e),
            }),
        )
            .into_response(),
    }
}

/// Distribute UMK request
#[derive(Debug, Deserialize, ToSchema)]
pub struct DistributeUmkRequest {
    /// Sender device ID
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub sender_device_id: Uuid,
    /// UMK encrypted with target device's public key (base64url)
    #[schema(example = "base64url-encoded-encrypted-umk")]
    pub encrypted_umk: String,
    /// Encryption nonce (base64url, 24 bytes)
    #[schema(example = "base64url-encoded-nonce")]
    pub nonce: String,
}

/// Distribute UMK response
#[derive(Debug, Serialize, ToSchema)]
pub struct DistributeUmkResponse {
    pub message: String,
}

/// Distribute UMK to a device
#[utoipa::path(
    post,
    path = "/api/devices/{id}/keys/umk",
    params(
        ("id" = Uuid, Path, description = "Target device ID")
    ),
    request_body = DistributeUmkRequest,
    responses(
        (status = 200, description = "UMK distributed", body = DistributeUmkResponse),
        (status = 400, description = "Invalid request", body = DeviceErrorResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
        (status = 403, description = "Not owner", body = DeviceErrorResponse),
        (status = 404, description = "Device not found", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
pub async fn distribute_umk<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>(
    State(state): State<AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>>,
    auth_user: AuthUserFull<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    Path(target_device_id): Path<Uuid>,
    Json(request): Json<DistributeUmkRequest>,
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
    // Decode fields
    let encrypted_umk = match base64_url::decode(&request.encrypted_umk) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid encrypted_umk encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let nonce = match base64_url::decode(&request.nonce) {
        Ok(n) if n.len() == 24 => n,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid nonce: must be 24 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid nonce encoding".to_string(),
                }),
            )
                .into_response();
        }
    };

    let handler = DistributeUmkHandler::new(state.device_repo(), state.device_encrypted_umk_repo());

    let command = DistributeUmkCommand {
        user_id: auth_user.user.id,
        target_device_id: DeviceId::from_uuid(target_device_id),
        sender_device_id: DeviceId::from_uuid(request.sender_device_id),
        encrypted_umk,
        nonce,
    };

    match handler.handle(command).await {
        Ok(_) => (
            StatusCode::OK,
            Json(DistributeUmkResponse {
                message: "UMK distributed successfully".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            let status = if e.is_not_found() {
                StatusCode::NOT_FOUND
            } else if e.is_forbidden() {
                StatusCode::FORBIDDEN
            } else if e.is_bad_request() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(DeviceErrorResponse { error: e.to_string() })).into_response()
        }
    }
}
