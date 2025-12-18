use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::context::AppContext;
use crate::security::token::{self, Bearer};
use domain::workspaces::permissions::{
    PERM_MEMBER_REMOVE, PERM_MEMBER_UPDATE_ROLE, PERM_MEMBER_VIEW,
};

use super::types::{
    UpdateMemberRoleRequest, WorkspaceMemberResponse, map_service_error, member_response_from,
    parse_role_kind, parse_system_role, require_permission,
};

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/members",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = [WorkspaceMemberResponse]))
)]
pub async fn list_members(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<WorkspaceMemberResponse>>, StatusCode> {
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, id, user_id, PERM_MEMBER_VIEW).await?;
    let members = ctx
        .workspace_service()
        .list_members(id)
        .await
        .map_err(map_service_error)?
        .into_iter()
        .map(member_response_from)
        .collect();
    Ok(Json(members))
}

#[utoipa::path(
    patch,
    path = "/api/workspaces/{id}/members/{user_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("user_id" = Uuid, Path, description = "Target user ID"),
    ),
    request_body = UpdateMemberRoleRequest,
    responses((status = 200, body = WorkspaceMemberResponse))
)]
pub async fn update_member_role(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path((workspace_id, member_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateMemberRoleRequest>,
) -> Result<Json<WorkspaceMemberResponse>, StatusCode> {
    let role_kind = parse_role_kind(body.role_kind.as_str())?;
    let system_role = parse_system_role(body.system_role.as_deref())?;
    match role_kind {
        domain::workspaces::roles::WorkspaceRoleKind::System => {
            if system_role.is_none() || body.custom_role_id.is_some() {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        domain::workspaces::roles::WorkspaceRoleKind::Custom => {
            if system_role.is_some() || body.custom_role_id.is_none() {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }

    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_UPDATE_ROLE).await?;

    ctx.workspace_service()
        .update_member_role(
            workspace_id,
            member_id,
            user_id,
            role_kind,
            system_role,
            body.custom_role_id,
        )
        .await
        .map_err(map_service_error)?;

    let updated = ctx
        .workspace_service()
        .list_members(workspace_id)
        .await
        .map_err(map_service_error)?
        .into_iter()
        .find(|m| m.user_id == member_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(member_response_from(updated)))
}

#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}/members/{user_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("user_id" = Uuid, Path, description = "Target user ID"),
    ),
    responses((status = 204))
)]
pub async fn remove_member(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path((workspace_id, member_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_REMOVE).await?;
    ctx.workspace_service()
        .remove_member(workspace_id, member_id, Some(user_id))
        .await
        .map_err(map_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}
