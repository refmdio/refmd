//! Pending device routes: create, list, get SAS, approve, reject

use application::types::DeviceId;
use application::encryption::{
    ApproveDeviceCommand, ApproveDeviceHandler, CreatePendingDeviceCommand,
    CreatePendingDeviceHandler, GetSasHandler, GetSasQuery, ListPendingDevicesHandler,
    ListPendingDevicesQuery,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    AuthUser, DeviceSubState, RecoveryOrPopUser,
    crypto_validation::{decode_ed25519_key, decode_signature, decode_x25519_key},
    try_decode,
};
use crate::client_ip::extract_client_ip;
use crate::routes::app_error_response;
use super::DeviceErrorResponse;

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
pub async fn create_pending_device(
    State(state): State<DeviceSubState>,
    headers: HeaderMap,
    auth_user: AuthUser,
    Json(request): Json<CreatePendingDeviceRequest>,
) -> impl IntoResponse {
    // Parse device type
    let device_type = try_decode!(
        crate::crypto_validation::parse_device_type(&request.device_type),
        DeviceErrorResponse
    );

    // Decode base64url fields with security validation
    let ecdh_public_key = try_decode!(
        decode_x25519_key("ecdh_public_key", &request.ecdh_public_key),
        DeviceErrorResponse
    );
    let signing_public_key = try_decode!(
        decode_ed25519_key("signing_public_key", &request.signing_public_key),
        DeviceErrorResponse
    );
    let client_nonce = try_decode!(
        crate::crypto_validation::decode_b64_exact("client_nonce", &request.client_nonce, 16),
        DeviceErrorResponse
    );

    let handler = CreatePendingDeviceHandler::new(
        state.pending_device_repo.clone(),
        state.user_identity_public_key_repo.clone(),
        state.device_event_bus.clone(),
    );

    // Extract client IP from headers
    let ip_address = extract_client_ip(&headers);

    let command = CreatePendingDeviceCommand {
        user_id: auth_user.user_id,
        device_name: request.device_name,
        device_type,
        ecdh_public_key,
        signing_public_key,
        client_nonce,
        ip_address: ip_address.clone(),
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = CreatePendingDeviceResponse {
                id: result.pending_device.id.to_string(),
                expires_at: result.pending_device.expires_at.to_rfc3339(),
                identity_signing_public_key: base64_url::encode(
                    &result.identity_signing_public_key,
                ),
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, DeviceErrorResponse, bad_request, not_found),
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
        (status = 400, description = "Invalid request", body = DeviceErrorResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
        (status = 403, description = "Not owner", body = DeviceErrorResponse),
        (status = 404, description = "Device not found", body = DeviceErrorResponse),
        (status = 410, description = "Device expired (pending device deleted)", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
pub async fn get_sas(
    State(state): State<DeviceSubState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let handler = GetSasHandler::new(
        state.pending_device_repo.clone(),
        state.device_event_bus.clone(),
    );

    let query = GetSasQuery {
        pending_device_id: DeviceId::from_uuid(id),
        user_id: auth_user.user_id,
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
        Err(e) => app_error_response!(e, DeviceErrorResponse, bad_request, not_found, forbidden, gone),
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
        (status = 400, description = "Invalid signature", body = DeviceErrorResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
        (status = 403, description = "Not owner", body = DeviceErrorResponse),
        (status = 404, description = "Device not found", body = DeviceErrorResponse),
        (status = 410, description = "Device expired (pending device deleted)", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
pub async fn approve_device(
    State(state): State<DeviceSubState>,
    pop_user: RecoveryOrPopUser,
    Path(id): Path<Uuid>,
    Json(request): Json<ApproveDeviceRequest>,
) -> impl IntoResponse {
    // Decode identity signature
    let identity_signature = try_decode!(
        decode_signature("identity_signature", &request.identity_signature),
        DeviceErrorResponse
    );

    let handler = ApproveDeviceHandler::new(
        state.device_repo.clone(),
        state.pending_device_repo.clone(),
        state.user_identity_public_key_repo.clone(),
    );

    let pending_device_id = DeviceId::from_uuid(id);

    let command = ApproveDeviceCommand {
        pending_device_id,
        user_id: pop_user.user_id,
        identity_signature,
    };

    match handler.handle(command).await {
        Ok(result) => {
            let response = ApproveDeviceResponse {
                id: result.device.id.to_string(),
                device_name: result.device.name,
                device_type: result.device.device_type,
                created_at: result.device.created_at.to_rfc3339(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, DeviceErrorResponse, not_found, gone, bad_request, forbidden),
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
pub async fn list_pending_devices(
    State(state): State<DeviceSubState>,
    auth_user: AuthUser,
) -> impl IntoResponse {
    let handler = ListPendingDevicesHandler::new(state.pending_device_repo.clone());

    let query = ListPendingDevicesQuery {
        user_id: auth_user.user_id,
    };

    match handler.handle(query).await {
        Ok(pending_devices) => {
            let response = ListPendingDevicesResponse {
                pending_devices: pending_devices
                    .into_iter()
                    .map(|d| PendingDeviceResponse {
                        id: d.id.to_string(),
                        name: d.name,
                        device_type: d.device_type,
                        ip_address: d.ip_address,
                        created_at: d.created_at.to_rfc3339(),
                        expires_at: d.expires_at.to_rfc3339(),
                    })
                    .collect(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, DeviceErrorResponse)
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
pub async fn reject_pending_device(
    State(state): State<DeviceSubState>,
    auth_user: AuthUser,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let pending_device_id = DeviceId::from_uuid(id);

    let handler = application::encryption::RejectPendingDeviceHandler::new(
        state.pending_device_repo.clone(),
        state.device_event_bus.clone(),
    );

    let command = application::encryption::RejectPendingDeviceCommand {
        user_id: auth_user.user_id,
        pending_device_id,
    };

    match handler.handle(command).await {
        Ok(()) => {
            (
                StatusCode::OK,
                Json(RejectPendingDeviceResponse {
                    message: "pending device rejected".to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => app_error_response!(e, DeviceErrorResponse, not_found, forbidden),
    }
}
