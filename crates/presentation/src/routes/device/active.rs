//! Active device routes: list, revoke, distribute UMK, get UMK

use application::types::DeviceId;
use application::encryption::{
    DistributeUmkCommand, DistributeUmkHandler, GetDeviceUmkHandler, GetDeviceUmkQuery,
    ListDevicesHandler, ListDevicesQuery,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    DeviceSubState, PopVerifiedUser,
    crypto_validation::{MAX_ENCRYPTED_KEY_BYTES, decode_encrypted_key_nonce},
    try_decode,
};
use crate::routes::app_error_response;
use super::DeviceErrorResponse;

/// Device response
#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceResponse {
    pub id: String,
    pub name: String,
    pub device_type: String,
    /// Ed25519 signing public key (base64url, 32 bytes) - for TOFU verification
    pub signing_public_key: String,
    /// ECDH public key (base64url, 32 bytes) - for KEK distribution
    pub ecdh_public_key: String,
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
pub async fn list_devices(
    State(state): State<DeviceSubState>,
    pop_user: PopVerifiedUser,
) -> impl IntoResponse {
    let current_device_id = pop_user.session.device_id;

    let handler = ListDevicesHandler::new(state.device_repo.clone());
    let query = ListDevicesQuery {
        user_id: pop_user.user_id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let response = ListDevicesResponse {
                devices: result
                    .devices
                    .into_iter()
                    .map(|d| DeviceResponse {
                        id: d.id.to_string(),
                        name: d.name,
                        device_type: d.device_type,
                        signing_public_key: base64_url::encode(&d.signing_public_key),
                        ecdh_public_key: base64_url::encode(&d.ecdh_public_key),
                        last_seen_at: d.last_seen_at.to_rfc3339(),
                        created_at: d.created_at.to_rfc3339(),
                        is_current: current_device_id == Some(d.id),
                    })
                    .collect(),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, DeviceErrorResponse)
    }
}

/// Revoke device request
#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeDeviceRequest {
    /// Identity signature of the revocation event (base64url, 64 bytes)
    #[schema(example = "base64url-encoded-signature")]
    pub identity_signature: String,
    /// Timestamp when revocation was requested (Unix milliseconds)
    #[schema(example = 1704067200000_i64)]
    pub revoked_at: i64,
}

/// Documents grouped by workspace that need DEK rotation
#[derive(Debug, Serialize, ToSchema)]
pub struct WorkspaceDocumentsForRotationResponse {
    pub workspace_id: Uuid,
    pub document_ids: Vec<Uuid>,
}

/// Non-fatal failures during rotation marking after device revocation
#[derive(Debug, Serialize, ToSchema)]
pub struct RotationMarkingFailuresResponse {
    /// Workspace IDs where KEK rotation marking failed
    pub failed_workspace_ids: Vec<Uuid>,
    /// Document IDs where DEK rotation marking failed
    pub failed_document_ids: Vec<Uuid>,
}

/// Revoke device response
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokeDeviceResponse {
    pub message: String,
    /// List of workspace IDs that now need KEK rotation for forward secrecy
    pub workspaces_needing_kek_rotation: Vec<Uuid>,
    /// Documents grouped by workspace that need DEK rotation for forward secrecy
    pub documents_needing_dek_rotation: Vec<WorkspaceDocumentsForRotationResponse>,
    /// Non-fatal failures during rotation marking (None if all succeeded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_marking_failures: Option<RotationMarkingFailuresResponse>,
}

/// Revoke (deauthorize) a device
#[utoipa::path(
    delete,
    path = "/api/devices/{id}",
    params(
        ("id" = Uuid, Path, description = "Device ID")
    ),
    request_body = RevokeDeviceRequest,
    responses(
        (status = 200, description = "Device revoked", body = RevokeDeviceResponse),
        (status = 400, description = "Invalid signature or timestamp", body = DeviceErrorResponse),
        (status = 401, description = "Not authenticated", body = DeviceErrorResponse),
        (status = 403, description = "Not owner", body = DeviceErrorResponse),
        (status = 404, description = "Device not found", body = DeviceErrorResponse),
    ),
    tag = "device"
)]
pub async fn revoke_device(
    State(state): State<DeviceSubState>,
    pop_user: PopVerifiedUser,
    Path(id): Path<Uuid>,
    Json(request): Json<RevokeDeviceRequest>,
) -> impl IntoResponse {
    use crate::crypto_validation::decode_signature;

    // Decode identity signature
    let identity_signature = try_decode!(
        decode_signature("identity_signature", &request.identity_signature),
        DeviceErrorResponse
    );

    let device_id = DeviceId::from_uuid(id);

    // Delegate to application layer handler
    use application::encryption::RevokeDeviceHandler;
    let handler = RevokeDeviceHandler::new(
        state.device_repo.clone(),
        state.user_identity_public_key_repo.clone(),
        state.device_revocation_event_repo.clone(),
        state.workspace_member_repo.clone(),
        state.workspace_repo.clone(),
        state.document_repo.clone(),
        state.document_key_repo.clone(),
    );

    let command = application::encryption::RevokeDeviceCommand {
        user_id: pop_user.user_id,
        device_id,
        revoking_device_id: pop_user.device.id,
        revoked_at: request.revoked_at,
        identity_signature,
        session_device_id: pop_user.session.device_id,
    };

    match handler.handle(command).await {
        Ok(result) => {
            if let Some(ref failures) = result.rotation_marking_failures {
                tracing::warn!(
                    failed_workspaces = ?failures.failed_workspace_ids,
                    failed_documents = ?failures.failed_document_ids,
                    "device revoked successfully but some rotation markers could not be saved"
                );
            }

            (
                StatusCode::OK,
                Json(RevokeDeviceResponse {
                    message: "device revoked".to_string(),
                    workspaces_needing_kek_rotation: result.workspaces_needing_kek_rotation,
                    documents_needing_dek_rotation: result
                        .documents_needing_dek_rotation
                        .into_iter()
                        .map(|w| WorkspaceDocumentsForRotationResponse {
                            workspace_id: w.workspace_id,
                            document_ids: w.document_ids,
                        })
                        .collect(),
                    rotation_marking_failures: result.rotation_marking_failures.map(|f| {
                        RotationMarkingFailuresResponse {
                            failed_workspace_ids: f.failed_workspace_ids,
                            failed_document_ids: f.failed_document_ids,
                        }
                    }),
                }),
            )
                .into_response()
        }
        Err(e) => app_error_response!(e, DeviceErrorResponse, bad_request, not_found, forbidden),
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
pub async fn distribute_umk(
    State(state): State<DeviceSubState>,
    pop_user: PopVerifiedUser,
    Path(target_device_id): Path<Uuid>,
    Json(request): Json<DistributeUmkRequest>,
) -> impl IntoResponse {
    // Decode fields (max 256 bytes for encrypted key)
    let (encrypted_umk, nonce) = try_decode!(
        decode_encrypted_key_nonce("encrypted_umk", &request.encrypted_umk, MAX_ENCRYPTED_KEY_BYTES, "nonce", &request.nonce),
        DeviceErrorResponse
    );

    let handler = DistributeUmkHandler::new(
        state.device_repo.clone(),
        state.device_encrypted_umk_repo.clone(),
        state.device_event_bus.clone(),
    );

    let command = DistributeUmkCommand {
        user_id: pop_user.user_id,
        target_device_id: DeviceId::from_uuid(target_device_id),
        sender_device_id: DeviceId::from_uuid(request.sender_device_id),
        authenticated_device_id: pop_user.device.id,
        encrypted_umk,
        nonce,
    };

    match handler.handle(command).await {
        Ok(_) => {
            (
                StatusCode::OK,
                Json(DistributeUmkResponse {
                    message: "UMK distributed successfully".to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => app_error_response!(e, DeviceErrorResponse, not_found, forbidden, bad_request),
    }
}

/// Get device UMK response
#[derive(Debug, Serialize, ToSchema)]
pub struct GetDeviceUmkResponse {
    /// Sender device ID
    pub sender_device_id: String,
    /// Sender's ECDH public key for shared secret derivation (base64url, 32 bytes)
    pub sender_ecdh_public_key: String,
    /// Sender's signing public key for TOFU verification (base64url, 32 bytes)
    pub sender_signing_public_key: String,
    /// UMK encrypted with shared secret (base64url)
    pub encrypted_umk: String,
    /// Encryption nonce (base64url, 24 bytes)
    pub nonce: String,
}

/// Get device's encrypted UMK
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
pub async fn get_device_umk(
    State(state): State<DeviceSubState>,
    pop_user: PopVerifiedUser,
    Path(device_id): Path<Uuid>,
) -> impl IntoResponse {
    let handler = GetDeviceUmkHandler::new(state.device_repo.clone(), state.device_encrypted_umk_repo.clone());
    let query = GetDeviceUmkQuery {
        user_id: pop_user.user_id,
        device_id: DeviceId::from_uuid(device_id),
        pop_device_id: pop_user.device.id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let response = GetDeviceUmkResponse {
                sender_device_id: result.sender_device_id.to_string(),
                sender_ecdh_public_key: base64_url::encode(&result.sender_ecdh_public_key),
                sender_signing_public_key: base64_url::encode(&result.sender_signing_public_key),
                encrypted_umk: base64_url::encode(&result.encrypted_umk),
                nonce: base64_url::encode(&result.nonce),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => app_error_response!(e, DeviceErrorResponse, not_found, forbidden),
    }
}
