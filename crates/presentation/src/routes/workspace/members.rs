//! Workspace member routes: list, change role, remove

use application::workspace::{
    ChangeMemberRoleCommand, ListMembersQuery, RemoveMemberCommand,
};
use application::types::{RoleId, WorkspaceId};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::WorkspaceSubState;
use crate::auth::AuthUser;
use crate::routes::app_error_response;
use super::WorkspaceErrorResponse;

/// Permission override entry
#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionOverrideResponse {
    pub permission: String,
    pub granted: bool,
}

/// Member detail response
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberDetailResponse {
    pub user_id: String,
    pub name: String,
    pub email: String,
    pub role_id: String,
    pub role_name: String,
    pub base_role: String,
    pub is_default: bool,
    pub joined_at: String,
    pub permission_overrides: Vec<PermissionOverrideResponse>,
}

/// List members response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListMembersResponse {
    pub members: Vec<MemberDetailResponse>,
}

/// List members of a workspace
#[utoipa::path(
    get,
    path = "/api/workspaces/{workspace_id}/members",
    params(("workspace_id" = Uuid, Path, description = "Workspace ID")),
    responses(
        (status = 200, description = "List of members", body = ListMembersResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
        (status = 404, description = "Not a member", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn list_members(
    State(state): State<WorkspaceSubState>,
    Path(workspace_id): Path<Uuid>,
    auth_user: AuthUser,
) -> impl IntoResponse {
    let handler = state.list_members_handler();

    let query = ListMembersQuery {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: auth_user.user_id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let members = result
                .members
                .into_iter()
                .map(|m| MemberDetailResponse {
                    user_id: m.member.user_id.to_string(),
                    name: m.user_name,
                    email: m.user_email,
                    role_id: m.role.id.to_string(),
                    role_name: m.role.name,
                    base_role: m.role.base_role,
                    is_default: m.member.is_default,
                    joined_at: m.member.joined_at.to_rfc3339(),
                    permission_overrides: m.role.permission_overrides
                        .into_iter()
                        .map(|(permission, granted)| PermissionOverrideResponse { permission, granted })
                        .collect(),
                })
                .collect();
            (StatusCode::OK, Json(ListMembersResponse { members })).into_response()
        }
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, not_found, forbidden),
    }
}

/// Change member role request
#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangeMemberRoleRequest {
    pub role_id: Uuid,
}

/// Change a member's role
#[utoipa::path(
    patch,
    path = "/api/workspaces/{workspace_id}/members/{user_id}",
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID"),
        ("user_id" = Uuid, Path, description = "Target user ID"),
    ),
    request_body = ChangeMemberRoleRequest,
    responses(
        (status = 204, description = "Role changed"),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
        (status = 404, description = "Member not found", body = WorkspaceErrorResponse),
        (status = 422, description = "Cannot demote last owner", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn change_member_role(
    State(state): State<WorkspaceSubState>,
    Path((workspace_id, target_user_id)): Path<(Uuid, Uuid)>,
    auth_user: AuthUser,
    Json(request): Json<ChangeMemberRoleRequest>,
) -> impl IntoResponse {
    let handler = state.change_member_role_handler();

    let command = ChangeMemberRoleCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: auth_user.user_id,
        target_user_id: application::types::UserId::from_uuid(target_user_id),
        new_role_id: RoleId::from_uuid(request.role_id),
    };

    match handler.handle(command).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, not_found, forbidden, conflict, unprocessable),
    }
}

/// Remove a member from workspace
#[utoipa::path(
    delete,
    path = "/api/workspaces/{workspace_id}/members/{user_id}",
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID"),
        ("user_id" = Uuid, Path, description = "Target user ID"),
    ),
    responses(
        (status = 204, description = "Member removed"),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
        (status = 404, description = "Member not found", body = WorkspaceErrorResponse),
        (status = 422, description = "Cannot remove last owner", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn remove_member(
    State(state): State<WorkspaceSubState>,
    Path((workspace_id, target_user_id)): Path<(Uuid, Uuid)>,
    auth_user: AuthUser,
) -> impl IntoResponse {
    let handler = state.remove_member_handler();

    let command = RemoveMemberCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: auth_user.user_id,
        target_user_id: application::types::UserId::from_uuid(target_user_id),
    };

    match handler.handle(command).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, not_found, forbidden, conflict, unprocessable),
    }
}
