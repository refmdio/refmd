//! Workspace role routes: list, create, update, delete

use application::workspace::{
    CreateRoleCommand, DeleteRoleCommand, ListRolesQuery, UpdateRoleCommand,
};
use application::types::{BaseRole, RoleId, WorkspaceId};
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

/// Role detail response
#[derive(Debug, Serialize, ToSchema)]
pub struct RoleDetailResponse {
    pub id: String,
    pub name: String,
    pub base_role: String,
    pub is_default: bool,
    pub created_at: String,
    pub permission_overrides: Vec<PermissionOverrideResponse>,
}

/// Permission override in a role response
#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionOverrideResponse {
    pub permission: String,
    pub granted: bool,
}

/// List roles response
#[derive(Debug, Serialize, ToSchema)]
pub struct ListRolesResponse {
    pub roles: Vec<RoleDetailResponse>,
}

fn role_to_response(r: application::dto::WorkspaceRoleDto) -> RoleDetailResponse {
    RoleDetailResponse {
        id: r.id.to_string(),
        name: r.name,
        base_role: r.base_role,
        is_default: r.is_default,
        created_at: r.created_at.to_rfc3339(),
        permission_overrides: r
            .permission_overrides
            .into_iter()
            .map(|(permission, granted)| PermissionOverrideResponse {
                permission,
                granted,
            })
            .collect(),
    }
}

/// List roles in a workspace
#[utoipa::path(
    get,
    path = "/api/workspaces/{workspace_id}/roles",
    params(("workspace_id" = Uuid, Path, description = "Workspace ID")),
    responses(
        (status = 200, description = "List of roles", body = ListRolesResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 404, description = "Not a member", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn list_roles(
    State(state): State<WorkspaceSubState>,
    Path(workspace_id): Path<Uuid>,
    auth_user: AuthUser,
) -> impl IntoResponse {
    let handler = state.list_roles_handler();

    let query = ListRolesQuery {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: auth_user.user_id,
    };

    match handler.handle(query).await {
        Ok(result) => {
            let roles = result.roles.into_iter().map(role_to_response).collect();
            (StatusCode::OK, Json(ListRolesResponse { roles })).into_response()
        }
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, not_found),
    }
}

/// Create role request
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
    pub base_role: String,
    #[serde(default)]
    pub is_default: bool,
}

/// Create a new role in a workspace
#[utoipa::path(
    post,
    path = "/api/workspaces/{workspace_id}/roles",
    params(("workspace_id" = Uuid, Path, description = "Workspace ID")),
    request_body = CreateRoleRequest,
    responses(
        (status = 201, description = "Role created", body = RoleDetailResponse),
        (status = 400, description = "Invalid input", body = WorkspaceErrorResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn create_role(
    State(state): State<WorkspaceSubState>,
    Path(workspace_id): Path<Uuid>,
    auth_user: AuthUser,
    Json(request): Json<CreateRoleRequest>,
) -> impl IntoResponse {
    let base_role = match parse_base_role(&request.base_role) {
        Ok(r) => r,
        Err(response) => return response,
    };

    let handler = state.create_role_handler();

    let command = CreateRoleCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        user_id: auth_user.user_id,
        name: request.name,
        base_role,
        is_default: request.is_default,
    };

    match handler.handle(command).await {
        Ok(result) => (StatusCode::CREATED, Json(role_to_response(result.role))).into_response(),
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, bad_request, not_found, forbidden),
    }
}

/// Update role request
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub base_role: Option<String>,
    pub is_default: Option<bool>,
    pub permission_overrides: Option<Vec<PermissionOverride>>,
}

/// Permission override
#[derive(Debug, Deserialize, ToSchema)]
pub struct PermissionOverride {
    pub permission: String,
    pub granted: bool,
}

/// Update a role
#[utoipa::path(
    patch,
    path = "/api/workspaces/{workspace_id}/roles/{role_id}",
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID"),
        ("role_id" = Uuid, Path, description = "Role ID"),
    ),
    request_body = UpdateRoleRequest,
    responses(
        (status = 200, description = "Role updated", body = RoleDetailResponse),
        (status = 400, description = "Invalid input", body = WorkspaceErrorResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
        (status = 404, description = "Role not found", body = WorkspaceErrorResponse),
        (status = 422, description = "Invalid operation (e.g. base_role change attempt)", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn update_role(
    State(state): State<WorkspaceSubState>,
    Path((workspace_id, role_id)): Path<(Uuid, Uuid)>,
    auth_user: AuthUser,
    Json(request): Json<UpdateRoleRequest>,
) -> impl IntoResponse {
    if request.base_role.is_some() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(WorkspaceErrorResponse {
                error: "base_role_immutable".to_string(),
            }),
        )
            .into_response();
    }

    let handler = state.update_role_handler();

    let permission_overrides = request.permission_overrides.map(|overrides| {
        overrides.into_iter().map(|o| (o.permission, o.granted)).collect()
    });

    let command = UpdateRoleCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        role_id: RoleId::from_uuid(role_id),
        user_id: auth_user.user_id,
        name: request.name,
        is_default: request.is_default,
        permission_overrides,
    };

    match handler.handle(command).await {
        Ok(result) => (StatusCode::OK, Json(role_to_response(result.role))).into_response(),
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, bad_request, not_found, forbidden),
    }
}

/// Delete role response
#[derive(Debug, Serialize, ToSchema)]
pub struct DeleteRoleResponse {
    pub invalidated_invitation_count: i64,
}

/// Delete a role
#[utoipa::path(
    delete,
    path = "/api/workspaces/{workspace_id}/roles/{role_id}",
    params(
        ("workspace_id" = Uuid, Path, description = "Workspace ID"),
        ("role_id" = Uuid, Path, description = "Role ID"),
    ),
    responses(
        (status = 200, description = "Role deleted", body = DeleteRoleResponse),
        (status = 400, description = "Invalid input", body = WorkspaceErrorResponse),
        (status = 401, description = "Not authenticated", body = WorkspaceErrorResponse),
        (status = 403, description = "Permission denied", body = WorkspaceErrorResponse),
        (status = 404, description = "Role not found", body = WorkspaceErrorResponse),
        (status = 409, description = "Role has members", body = WorkspaceErrorResponse),
    ),
    tag = "workspace"
)]
pub async fn delete_role(
    State(state): State<WorkspaceSubState>,
    Path((workspace_id, role_id)): Path<(Uuid, Uuid)>,
    auth_user: AuthUser,
) -> impl IntoResponse {
    let handler = state.delete_role_handler();

    let command = DeleteRoleCommand {
        workspace_id: WorkspaceId::from_uuid(workspace_id),
        role_id: RoleId::from_uuid(role_id),
        user_id: auth_user.user_id,
    };

    match handler.handle(command).await {
        Ok(result) => (
            StatusCode::OK,
            Json(DeleteRoleResponse {
                invalidated_invitation_count: result.invalidated_invitation_count,
            }),
        )
            .into_response(),
        Err(e) => app_error_response!(e, WorkspaceErrorResponse, bad_request, not_found, forbidden, conflict),
    }
}

// Allow large error type: axum::response::Response is inherently large and
// must be returned as-is (no Box indirection possible with IntoResponse).
#[allow(clippy::result_large_err)]
fn parse_base_role(s: &str) -> Result<BaseRole, axum::response::Response> {
    match s {
        "admin" => Ok(BaseRole::Admin),
        "editor" => Ok(BaseRole::Editor),
        "viewer" => Ok(BaseRole::Viewer),
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(WorkspaceErrorResponse {
                error: format!("invalid base_role: '{}'. Must be one of: admin, editor, viewer", s),
            }),
        ).into_response()),
    }
}
