//! Workspace member device routes: list active devices for a workspace member

use application::encryption::ListMemberDevicesQuery;
use application::types::{UserId, WorkspaceId};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::WorkspaceSubState;
use crate::auth::AuthUser;
use crate::routes::app_error_response;
use super::WorkspaceErrorResponse;

/// Member device public key response
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberDeviceResponse {
    pub device_id: String,
    pub signing_public_key: String,
    pub ecdh_public_key: String,
    pub created_at: String,
}

/// List member devices response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListMemberDevicesResponse {
    pub devices: Vec<MemberDeviceResponse>,
}

/// List active devices for a workspace member
#[utoipa::path(
    get,
    path = "/api/workspaces/{workspace_id}/members/{user_id}/devices",
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID"),
        ("user_id" = Uuid, Path, description = "Target member user ID"),
    ),
    responses(
        (status = 200, description = "List of member's active devices", body = ListMemberDevicesResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
        (status = 404, description = "Not a member", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn list_member_devices(
    State(state): State<WorkspaceSubState>,
    Path((workspace_id, target_user_id)): Path<(Uuid, Uuid)>,
    auth_user: AuthUser,
) -> impl IntoResponse {
    let handler = state.list_member_devices_handler();

    let query = ListMemberDevicesQuery {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        caller_user_id: auth_user.user_id,
        target_user_id: UserId::from_uuid(target_user_id),
    };

    match handler.handle(query).await {
        Ok(result) => {
            let devices = result
                .devices
                .into_iter()
                .map(|d| MemberDeviceResponse {
                    device_id: d.device_id.to_string(),
                    signing_public_key: base64_url::encode(&d.signing_public_key),
                    ecdh_public_key: base64_url::encode(&d.ecdh_public_key),
                    created_at: d.created_at.to_rfc3339(),
                })
                .collect();
            (StatusCode::OK, Json(ListMemberDevicesResponse { devices })).into_response()
        }
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, not_found, forbidden),
    }
}
