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
    GetSasQuery, ListPendingDevicesHandler, ListPendingDevicesQuery,
};
use application::identity::RegistrationService;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{delete, get, post},
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use tower_governor::GovernorLayer;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    AppState, AuthUserFull, DeviceEvent,
    auth::verify_pop,
    crypto_validation::{is_valid_ed25519_public_key, is_valid_x25519_public_key},
    rate_limit::create_device_rate_limit_config,
};

/// Extract client IP from request headers
///
/// # Security Note
///
/// This function trusts proxy headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP).
/// These headers can be spoofed by clients if the server is not behind a trusted proxy.
///
/// In production, ensure the server is deployed behind a trusted reverse proxy that:
/// 1. Strips or overwrites these headers from client requests
/// 2. Sets the correct client IP in these headers
///
/// The IP is used for informational purposes (showing to the approving user)
/// and is not used for security decisions.
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    // Priority: CF-Connecting-IP > X-Real-IP > X-Forwarded-For (last entry)
    // CF-Connecting-IP and X-Real-IP are typically set by trusted proxies
    // and are harder to spoof through multiple proxy hops

    // Try CF-Connecting-IP (Cloudflare - most trusted)
    if let Some(cf_ip) = headers.get("cf-connecting-ip")
        && let Ok(value) = cf_ip.to_str()
    {
        let ip = value.trim();
        if is_valid_ip(ip) {
            return Some(ip.to_string());
        }
    }

    // Try X-Real-IP (nginx - single IP, trusted)
    if let Some(xri) = headers.get("x-real-ip")
        && let Ok(value) = xri.to_str()
    {
        let ip = value.trim();
        if is_valid_ip(ip) {
            return Some(ip.to_string());
        }
    }

    // Try X-Forwarded-For (take rightmost non-private IP for better security)
    // The rightmost IP is the one added by the closest trusted proxy
    if let Some(xff) = headers.get("x-forwarded-for")
        && let Ok(value) = xff.to_str()
    {
        // Split and reverse to get rightmost first
        for ip in value.split(',').rev() {
            let ip = ip.trim();
            if is_valid_ip(ip) && !is_private_ip(ip) {
                return Some(ip.to_string());
            }
        }
        // If all IPs are private, take the leftmost (original client)
        if let Some(ip) = value.split(',').next() {
            let ip = ip.trim();
            if is_valid_ip(ip) {
                return Some(ip.to_string());
            }
        }
    }

    None
}

/// Basic IP address validation
fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// Check if IP is a private/reserved address
fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(ipv4) => {
                ipv4.is_private()
                    || ipv4.is_loopback()
                    || ipv4.is_link_local()
                    || ipv4.is_unspecified()
            }
            std::net::IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
        }
    } else {
        false
    }
}

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
            post(
                create_pending_device::<
                    U,
                    S,
                    US,
                    UIP,
                    UEM,
                    UEI,
                    WR,
                    WMR,
                    WRR,
                    DR,
                    DUR,
                    WKR,
                    DKR,
                    RS,
                    DER,
                    PDR,
                    UMKR,
                >,
            ),
        )
        .layer(GovernorLayer {
            config: device_rate_limit,
        });

    // Non-rate-limited routes (authenticated endpoints)
    let other_routes = Router::new()
        .route(
            "/pending",
            get(list_pending_devices::<
                U,
                S,
                US,
                UIP,
                UEM,
                UEI,
                WR,
                WMR,
                WRR,
                DR,
                DUR,
                WKR,
                DKR,
                RS,
                DER,
                PDR,
                UMKR,
            >),
        )
        .route(
            "/pending/{id}/sas",
            get(get_sas::<
                U,
                S,
                US,
                UIP,
                UEM,
                UEI,
                WR,
                WMR,
                WRR,
                DR,
                DUR,
                WKR,
                DKR,
                RS,
                DER,
                PDR,
                UMKR,
            >),
        )
        .route(
            "/pending/{id}/events",
            get(pending_device_events::<
                U,
                S,
                US,
                UIP,
                UEM,
                UEI,
                WR,
                WMR,
                WRR,
                DR,
                DUR,
                WKR,
                DKR,
                RS,
                DER,
                PDR,
                UMKR,
            >),
        )
        .route(
            "/pending/{id}/approve",
            post(
                approve_device::<
                    U,
                    S,
                    US,
                    UIP,
                    UEM,
                    UEI,
                    WR,
                    WMR,
                    WRR,
                    DR,
                    DUR,
                    WKR,
                    DKR,
                    RS,
                    DER,
                    PDR,
                    UMKR,
                >,
            ),
        )
        .route(
            "/pending/{id}",
            delete(
                reject_pending_device::<
                    U,
                    S,
                    US,
                    UIP,
                    UEM,
                    UEI,
                    WR,
                    WMR,
                    WRR,
                    DR,
                    DUR,
                    WKR,
                    DKR,
                    RS,
                    DER,
                    PDR,
                    UMKR,
                >,
            ),
        )
        .route(
            "/events",
            get(device_events::<
                U,
                S,
                US,
                UIP,
                UEM,
                UEI,
                WR,
                WMR,
                WRR,
                DR,
                DUR,
                WKR,
                DKR,
                RS,
                DER,
                PDR,
                UMKR,
            >),
        )
        .route(
            "/",
            get(list_devices::<
                U,
                S,
                US,
                UIP,
                UEM,
                UEI,
                WR,
                WMR,
                WRR,
                DR,
                DUR,
                WKR,
                DKR,
                RS,
                DER,
                PDR,
                UMKR,
            >),
        )
        .route(
            "/{id}",
            delete(
                revoke_device::<
                    U,
                    S,
                    US,
                    UIP,
                    UEM,
                    UEI,
                    WR,
                    WMR,
                    WRR,
                    DR,
                    DUR,
                    WKR,
                    DKR,
                    RS,
                    DER,
                    PDR,
                    UMKR,
                >,
            ),
        )
        .route(
            "/{id}/keys/umk",
            post(
                distribute_umk::<
                    U,
                    S,
                    US,
                    UIP,
                    UEM,
                    UEI,
                    WR,
                    WMR,
                    WRR,
                    DR,
                    DUR,
                    WKR,
                    DKR,
                    RS,
                    DER,
                    PDR,
                    UMKR,
                >,
            )
            .get(
                get_device_umk::<
                    U,
                    S,
                    US,
                    UIP,
                    UEM,
                    UEI,
                    WR,
                    WMR,
                    WRR,
                    DR,
                    DUR,
                    WKR,
                    DKR,
                    RS,
                    DER,
                    PDR,
                    UMKR,
                >,
            ),
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
pub async fn create_pending_device<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    headers: HeaderMap,
    auth_user: AuthUserFull<
        U,
        S,
        US,
        UIP,
        UEM,
        UEI,
        WR,
        WMR,
        WRR,
        DR,
        DUR,
        WKR,
        DKR,
        RS,
        DER,
        PDR,
        UMKR,
    >,
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

    // Decode base64url fields with security validation
    let ecdh_public_key = match base64_url::decode(&request.ecdh_public_key) {
        Ok(k) if k.len() == 32 && is_valid_x25519_public_key(&k) => k,
        Ok(k) if k.len() != 32 => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid ecdh_public_key: must be 32 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid ecdh_public_key: low-order point rejected".to_string(),
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
        Ok(k) if k.len() == 32 && is_valid_ed25519_public_key(&k) => k,
        Ok(k) if k.len() != 32 => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid signing_public_key: must be 32 bytes".to_string(),
                }),
            )
                .into_response();
        }
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "invalid signing_public_key: small-order point rejected".to_string(),
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

    // Extract client IP from headers
    let ip_address = extract_client_ip(&headers);

    let command = CreatePendingDeviceCommand {
        user_id: auth_user.user.id,
        device_name: request.device_name,
        device_type,
        ecdh_public_key,
        signing_public_key,
        client_nonce,
        ip_address: ip_address.clone(),
    };

    match handler.handle(command).await {
        Ok(result) => {
            // Publish SSE event for existing devices
            state
                .device_event_bus()
                .pending_created(
                    result.pending_device.id,
                    auth_user.user.id,
                    result.pending_device.name.clone(),
                    result.pending_device.device_type.as_str().to_string(),
                    ip_address,
                    result.pending_device.expires_at,
                )
                .await;

            let response = CreatePendingDeviceResponse {
                id: result.pending_device.id.to_string(),
                expires_at: result.pending_device.expires_at.to_rfc3339(),
                identity_signing_public_key: base64_url::encode(
                    &result.identity_signing_public_key,
                ),
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
            (
                status,
                Json(DeviceErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Get SAS response
///
/// Get SAS response - returns device public keys for client-side SAS calculation.
///
/// For MITM detection, clients MUST calculate SAS locally using
/// `device_signing_public_key`, `device_ecdh_public_key`, `client_nonce`
/// and their LOCAL identity signing public key.
#[derive(Debug, Serialize, ToSchema)]
pub struct GetSasResponse {
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
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    auth_user: AuthUserFull<
        U,
        S,
        US,
        UIP,
        UEM,
        UEI,
        WR,
        WMR,
        WRR,
        DR,
        DUR,
        WKR,
        DKR,
        RS,
        DER,
        PDR,
        UMKR,
    >,
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
    let handler = GetSasHandler::new(state.pending_device_repo());

    let query = GetSasQuery {
        pending_device_id: DeviceId::from_uuid(id),
        user_id: auth_user.user.id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let response = GetSasResponse {
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
            (
                status,
                Json(DeviceErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
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
pub async fn approve_device<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    auth_user: AuthUserFull<
        U,
        S,
        US,
        UIP,
        UEM,
        UEI,
        WR,
        WMR,
        WRR,
        DR,
        DUR,
        WKR,
        DKR,
        RS,
        DER,
        PDR,
        UMKR,
    >,
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

    let pending_device_id = DeviceId::from_uuid(id);

    let command = ApproveDeviceCommand {
        pending_device_id,
        user_id: auth_user.user.id,
        identity_signature,
    };

    match handler.handle(command).await {
        Ok(result) => {
            // Note: SSE event is NOT emitted here.
            // It will be emitted when UMK is distributed via distribute_umk endpoint.
            // This ensures the new device only receives the event after UMK is available.

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
            (
                status,
                Json(DeviceErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Pending device response
#[derive(Debug, Serialize, ToSchema)]
pub struct PendingDeviceResponse {
    pub id: String,
    pub name: String,
    pub device_type: String,
    pub ip_address: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

/// List pending devices response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListPendingDevicesResponse {
    pub pending_devices: Vec<PendingDeviceResponse>,
}

/// List pending devices awaiting approval
#[utoipa::path(
    get,
    path = "/api/devices/pending",
    responses(
        (status = 200, description = "List of pending devices", body = ListPendingDevicesResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
pub async fn list_pending_devices<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    auth_user: AuthUserFull<
        U,
        S,
        US,
        UIP,
        UEM,
        UEI,
        WR,
        WMR,
        WRR,
        DR,
        DUR,
        WKR,
        DKR,
        RS,
        DER,
        PDR,
        UMKR,
    >,
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
    let handler = ListPendingDevicesHandler::new(state.pending_device_repo());

    let query = ListPendingDevicesQuery {
        user_id: auth_user.user.id,
    };

    match handler.handle(query).await {
        Ok(pending_devices) => {
            let response = ListPendingDevicesResponse {
                pending_devices: pending_devices
                    .into_iter()
                    .map(|d| PendingDeviceResponse {
                        id: d.id.to_string(),
                        name: d.name,
                        device_type: d.device_type.as_str().to_string(),
                        ip_address: d.ip_address,
                        created_at: d.created_at.to_rfc3339(),
                        expires_at: d.expires_at.to_rfc3339(),
                    })
                    .collect(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(DeviceErrorResponse {
                error: format!("failed to list pending devices: {}", e),
            }),
        )
            .into_response(),
    }
}

/// Reject pending device response
#[derive(Debug, Serialize, ToSchema)]
pub struct RejectPendingDeviceResponse {
    pub message: String,
}

/// Reject a pending device
#[utoipa::path(
    delete,
    path = "/api/devices/pending/{id}",
    params(
        ("id" = Uuid, Path, description = "Pending device ID")
    ),
    responses(
        (status = 200, description = "Pending device rejected", body = RejectPendingDeviceResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
        (status = 403, description = "Not owner", body = DeviceErrorResponse),
        (status = 404, description = "Device not found", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
pub async fn reject_pending_device<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    auth_user: AuthUserFull<
        U,
        S,
        US,
        UIP,
        UEM,
        UEI,
        WR,
        WMR,
        WRR,
        DR,
        DUR,
        WKR,
        DKR,
        RS,
        DER,
        PDR,
        UMKR,
    >,
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
    let pending_device_repo = state.pending_device_repo();
    let pending_device_id = DeviceId::from_uuid(id);

    // Find pending device
    let pending_device = match pending_device_repo.find_by_id(pending_device_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(DeviceErrorResponse {
                    error: "pending device not found".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(DeviceErrorResponse {
                    error: format!("failed to find pending device: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Verify ownership
    if pending_device.user_id != auth_user.user.id {
        return (
            StatusCode::FORBIDDEN,
            Json(DeviceErrorResponse {
                error: "pending device does not belong to this user".to_string(),
            }),
        )
            .into_response();
    }

    // Delete pending device
    match pending_device_repo.delete(pending_device_id).await {
        Ok(()) => {
            // Publish SSE event for the new device waiting
            state
                .device_event_bus()
                .pending_removed(pending_device_id, auth_user.user.id)
                .await;

            (
                StatusCode::OK,
                Json(RejectPendingDeviceResponse {
                    message: "pending device rejected".to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(DeviceErrorResponse {
                error: format!("failed to reject pending device: {}", e),
            }),
        )
            .into_response(),
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
pub async fn list_devices<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    headers: HeaderMap,
    auth_user: AuthUserFull<
        U,
        S,
        US,
        UIP,
        UEM,
        UEI,
        WR,
        WMR,
        WRR,
        DR,
        DUR,
        WKR,
        DKR,
        RS,
        DER,
        PDR,
        UMKR,
    >,
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
    // Verify PoP (Proof of Possession) - required for device management operations
    if let Err(e) = verify_pop(
        &headers,
        auth_user.user.id,
        state.device_repo().as_ref(),
        &state.challenge_store(),
    )
    .await
    {
        return e.into_response();
    }

    let device_repo = state.device_repo();
    let current_device_id = auth_user.session.device_id;

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
                        is_current: current_device_id == Some(d.id),
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
    /// List of workspace IDs that now need KEK rotation for forward secrecy
    pub workspaces_needing_kek_rotation: Vec<Uuid>,
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
pub async fn revoke_device<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    headers: HeaderMap,
    auth_user: AuthUserFull<
        U,
        S,
        US,
        UIP,
        UEM,
        UEI,
        WR,
        WMR,
        WRR,
        DR,
        DUR,
        WKR,
        DKR,
        RS,
        DER,
        PDR,
        UMKR,
    >,
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
    // Verify PoP (Proof of Possession) - required for device revocation
    if let Err(e) = verify_pop(
        &headers,
        auth_user.user.id,
        state.device_repo().as_ref(),
        &state.challenge_store(),
    )
    .await
    {
        return e.into_response();
    }

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

    // Prevent revoking current device
    if auth_user.session.device_id == Some(device_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(DeviceErrorResponse {
                error: "cannot revoke current device".to_string(),
            }),
        )
            .into_response();
    }

    // Revoke device
    device.revoke();

    if let Err(e) = device_repo.save(&device).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(DeviceErrorResponse {
                error: format!("failed to revoke device: {}", e),
            }),
        )
            .into_response();
    }

    // Mark all user's workspaces as needing KEK rotation
    // This ensures forward secrecy after device compromise
    let member_repo = state.workspace_member_repo();
    let workspace_repo = state.workspace_repo();

    let workspace_ids_needing_rotation = match member_repo.find_by_user_id(auth_user.user.id).await
    {
        Ok(members) => {
            let mut workspace_ids = Vec::new();
            for member in members {
                // Get workspace and mark for rotation
                if let Ok(Some(mut workspace)) =
                    workspace_repo.find_by_id(member.workspace_id).await
                {
                    workspace.mark_needs_kek_rotation();
                    if let Err(e) = workspace_repo.save(&workspace).await {
                        tracing::error!(
                            "failed to mark workspace {} for KEK rotation: {}",
                            workspace.id,
                            e
                        );
                    } else {
                        workspace_ids.push(workspace.id.as_uuid());
                    }
                }
            }
            workspace_ids
        }
        Err(e) => {
            tracing::error!(
                "failed to find user workspaces for KEK rotation marking: {}",
                e
            );
            Vec::new()
        }
    };

    (
        StatusCode::OK,
        Json(RevokeDeviceResponse {
            message: "device revoked".to_string(),
            workspaces_needing_kek_rotation: workspace_ids_needing_rotation,
        }),
    )
        .into_response()
}

/// Distribute UMK request
#[derive(Debug, Deserialize, ToSchema)]
pub struct DistributeUmkRequest {
    /// Sender device ID
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub sender_device_id: Uuid,
    /// Pending device ID (for SSE notification to the new device)
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub pending_device_id: Uuid,
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
#[allow(clippy::too_many_arguments)]
pub async fn distribute_umk<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    headers: HeaderMap,
    auth_user: AuthUserFull<
        U,
        S,
        US,
        UIP,
        UEM,
        UEI,
        WR,
        WMR,
        WRR,
        DR,
        DUR,
        WKR,
        DKR,
        RS,
        DER,
        PDR,
        UMKR,
    >,
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
    // Verify PoP (Proof of Possession) - required for key distribution operations
    if let Err(e) = verify_pop(
        &headers,
        auth_user.user.id,
        state.device_repo().as_ref(),
        &state.challenge_store(),
    )
    .await
    {
        return e.into_response();
    }

    // Validate sender_device_id matches the PoP device
    // This prevents attackers from submitting UMK encrypted with a different device's key
    let pop_device_id = match headers
        .get(crate::POP_DEVICE_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => DeviceId::from_uuid(id),
        None => {
            // This shouldn't happen since verify_pop already validated
            return (
                StatusCode::BAD_REQUEST,
                Json(DeviceErrorResponse {
                    error: "missing or invalid PoP device ID".to_string(),
                }),
            )
                .into_response();
        }
    };

    if pop_device_id != DeviceId::from_uuid(request.sender_device_id) {
        return (
            StatusCode::FORBIDDEN,
            Json(DeviceErrorResponse {
                error: "sender_device_id must match the PoP authenticated device".to_string(),
            }),
        )
            .into_response();
    }

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
        Ok(_) => {
            // Publish SSE event now that UMK is available for the new device
            state
                .device_event_bus()
                .pending_approved(
                    DeviceId::from_uuid(request.pending_device_id),
                    auth_user.user.id,
                    DeviceId::from_uuid(target_device_id),
                )
                .await;

            (
                StatusCode::OK,
                Json(DistributeUmkResponse {
                    message: "UMK distributed successfully".to_string(),
                }),
            )
                .into_response()
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
            (
                status,
                Json(DeviceErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// Get device UMK response
#[derive(Debug, Serialize, ToSchema)]
pub struct GetDeviceUmkResponse {
    /// Sender device ID
    pub sender_device_id: String,
    /// Sender's ECDH public key for shared secret derivation (base64url, 32 bytes)
    pub sender_ecdh_public_key: String,
    /// UMK encrypted with shared secret (base64url)
    pub encrypted_umk: String,
    /// Encryption nonce (base64url, 24 bytes)
    pub nonce: String,
}

/// Get device's encrypted UMK
///
/// Retrieves the encrypted UMK that was distributed to this device.
/// The device uses its ECDH private key and the sender's ECDH public key
/// to derive the shared secret and decrypt the UMK.
#[utoipa::path(
    get,
    path = "/api/devices/{id}/keys/umk",
    params(
        ("id" = Uuid, Path, description = "Device ID")
    ),
    responses(
        (status = 200, description = "Encrypted UMK data", body = GetDeviceUmkResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
        (status = 403, description = "Device does not belong to this user", body = DeviceErrorResponse),
        (status = 404, description = "UMK not found for this device", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
#[allow(clippy::too_many_arguments)]
pub async fn get_device_umk<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    auth_user: AuthUserFull<
        U,
        S,
        US,
        UIP,
        UEM,
        UEI,
        WR,
        WMR,
        WRR,
        DR,
        DUR,
        WKR,
        DKR,
        RS,
        DER,
        PDR,
        UMKR,
    >,
    Path(device_id): Path<Uuid>,
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
    let device_id = DeviceId::from_uuid(device_id);
    let device_repo = state.device_repo();

    // Verify the target device exists and belongs to this user
    let target_device = match device_repo.find_by_id(device_id).await {
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
                    error: format!("failed to retrieve device: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Verify device belongs to the authenticated user
    // Use 404 instead of 403 to prevent device ID enumeration
    if target_device.user_id != auth_user.user.id {
        return (
            StatusCode::NOT_FOUND,
            Json(DeviceErrorResponse {
                error: "device not found".to_string(),
            }),
        )
            .into_response();
    }

    // Verify device is not revoked
    // Use 404 to prevent leaking revocation status to potential attackers
    if target_device.is_revoked() {
        return (
            StatusCode::NOT_FOUND,
            Json(DeviceErrorResponse {
                error: "device not found".to_string(),
            }),
        )
            .into_response();
    }

    // Find the encrypted UMK for this device
    let umk_repo = state.device_encrypted_umk_repo();
    let device_umk = match umk_repo
        .find_by_user_and_device(auth_user.user.id, device_id)
        .await
    {
        Ok(Some(umk)) => umk,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(DeviceErrorResponse {
                    error: "UMK not found for this device".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(DeviceErrorResponse {
                    error: format!("failed to retrieve UMK: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Find the sender device to get their ECDH public key
    let sender_device = match device_repo.find_by_id(device_umk.sender_device_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(DeviceErrorResponse {
                    error: "sender device not found".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(DeviceErrorResponse {
                    error: format!("failed to retrieve sender device: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Verify sender device belongs to the same user
    if sender_device.user_id != auth_user.user.id {
        return (
            StatusCode::FORBIDDEN,
            Json(DeviceErrorResponse {
                error: "sender device does not belong to this user".to_string(),
            }),
        )
            .into_response();
    }

    // Note: We don't check if sender device is revoked because:
    // 1. The UMK was already distributed before revocation
    // 2. The encrypted data is still valid for decryption
    // 3. The new device needs to retrieve UMK regardless of sender's current status

    let response = GetDeviceUmkResponse {
        sender_device_id: device_umk.sender_device_id.to_string(),
        sender_ecdh_public_key: base64_url::encode(&sender_device.ecdh_public_key),
        encrypted_umk: base64_url::encode(&device_umk.encrypted_umk),
        nonce: base64_url::encode(&device_umk.nonce),
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// SSE endpoint for existing devices to receive pending device notifications
///
/// Streams events when:
/// - A new pending device is created for this user
/// - A pending device is approved
/// - A pending device expires/is removed
#[utoipa::path(
    get,
    path = "/api/devices/events",
    tag = "device",
    responses(
        (status = 200, description = "SSE event stream", content_type = "text/event-stream"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn device_events<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    auth_user: AuthUserFull<
        U,
        S,
        US,
        UIP,
        UEM,
        UEI,
        WR,
        WMR,
        WRR,
        DR,
        DUR,
        WKR,
        DKR,
        RS,
        DER,
        PDR,
        UMKR,
    >,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>>
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
    let user_id = auth_user.user.id.to_string();
    let receiver = state.device_event_bus().subscribe();

    let stream =
        BroadcastStream::<DeviceEvent>::new(receiver).filter_map(move |result| match result {
            Ok(event) if event.user_id() == user_id => {
                let json = serde_json::to_string(&event).ok()?;
                Some(Ok(Event::default().data(json)))
            }
            _ => None,
        });

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

/// SSE endpoint for a new device waiting for approval
///
/// Streams events when:
/// - This pending device is approved
/// - This pending device expires/is removed
#[utoipa::path(
    get,
    path = "/api/devices/pending/{id}/events",
    tag = "device",
    params(
        ("id" = Uuid, Path, description = "Pending device ID")
    ),
    responses(
        (status = 200, description = "SSE event stream", content_type = "text/event-stream"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pending device not found")
    ),
    security(
        ("session_cookie" = [])
    )
)]
pub async fn pending_device_events<
    U,
    S,
    US,
    UIP,
    UEM,
    UEI,
    WR,
    WMR,
    WRR,
    DR,
    DUR,
    WKR,
    DKR,
    RS,
    DER,
    PDR,
    UMKR,
>(
    State(state): State<
        AppState<U, S, US, UIP, UEM, UEI, WR, WMR, WRR, DR, DUR, WKR, DKR, RS, DER, PDR, UMKR>,
    >,
    auth_user: AuthUserFull<
        U,
        S,
        US,
        UIP,
        UEM,
        UEI,
        WR,
        WMR,
        WRR,
        DR,
        DUR,
        WKR,
        DKR,
        RS,
        DER,
        PDR,
        UMKR,
    >,
    Path(id): Path<Uuid>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>>
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
    let pending_id = id.to_string();
    let user_id = auth_user.user.id.to_string();
    let receiver = state.device_event_bus().subscribe();

    let stream =
        BroadcastStream::<DeviceEvent>::new(receiver).filter_map(move |result| match result {
            Ok(ref event) if event.pending_id() == pending_id && event.user_id() == user_id => {
                let json = serde_json::to_string(&event).ok()?;
                Some(Ok(Event::default().data(json)))
            }
            _ => None,
        });

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
