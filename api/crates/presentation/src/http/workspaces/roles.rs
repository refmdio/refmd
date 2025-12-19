use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::context::AppContext;
use crate::security::token::{self, Bearer};
use domain::access::permissions::{PERM_MEMBER_INVITE, PERM_MEMBER_UPDATE_ROLE, PERM_MEMBER_VIEW};

use super::types::{
    CreateWorkspaceRoleRequest, UpdateWorkspaceRoleRequest, WorkspaceRoleResponse,
    map_service_error, normalize_overrides, parse_base_role, parse_optional_base_role,
    require_any_permission, require_permission, role_response_from, validate_base_role,
};

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/roles",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = [WorkspaceRoleResponse]))
)]
pub async fn list_roles(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<WorkspaceRoleResponse>>, crate::http::error::ApiError> {
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    require_any_permission(
        &ctx,
        id,
        user_id,
        &[
            PERM_MEMBER_VIEW,
            PERM_MEMBER_UPDATE_ROLE,
            PERM_MEMBER_INVITE,
        ],
    )
    .await?;
    let roles = ctx
        .workspace_service()
        .list_roles(id)
        .await
        .map_err(map_service_error)?
        .into_iter()
        .map(role_response_from)
        .collect();
    Ok(Json(roles))
}

#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/roles",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    request_body = CreateWorkspaceRoleRequest,
    responses((status = 200, body = WorkspaceRoleResponse))
)]
pub async fn create_role(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateWorkspaceRoleRequest>,
) -> Result<Json<WorkspaceRoleResponse>, crate::http::error::ApiError> {
    if body.name.trim().is_empty() || !validate_base_role(body.base_role.as_str()) {
        return Err(crate::http::error::ApiError::bad_request("invalid_role"));
    }
    let base_role = parse_base_role(body.base_role.as_str())?;
    let overrides = normalize_overrides(body.overrides)?;
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    require_permission(&ctx, id, user_id, PERM_MEMBER_UPDATE_ROLE).await?;
    let record = ctx
        .workspace_service()
        .create_role(
            id,
            user_id,
            body.name.trim(),
            base_role,
            body.description.as_deref(),
            body.priority.unwrap_or(0),
            &overrides,
        )
        .await
        .map_err(map_service_error)?;
    Ok(Json(role_response_from(record)))
}

#[utoipa::path(
    patch,
    path = "/api/workspaces/{id}/roles/{role_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("role_id" = Uuid, Path, description = "Role ID"),
    ),
    request_body = UpdateWorkspaceRoleRequest,
    responses((status = 200, body = WorkspaceRoleResponse))
)]
pub async fn update_role(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path((workspace_id, role_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateWorkspaceRoleRequest>,
) -> Result<Json<WorkspaceRoleResponse>, crate::http::error::ApiError> {
    if body
        .base_role
        .as_deref()
        .is_some_and(|base| !validate_base_role(base))
    {
        return Err(crate::http::error::ApiError::bad_request("invalid_base_role"));
    }
    let base_role = parse_optional_base_role(body.base_role.as_deref())?;
    let overrides_vec = normalize_overrides(body.overrides.clone())?;
    let overrides_opt = if body.overrides.is_some() {
        Some(overrides_vec.as_slice())
    } else {
        None
    };
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_UPDATE_ROLE).await?;
    let mut record = ctx
        .workspace_service()
        .update_role(
            workspace_id,
            user_id,
            role_id,
            body.name.as_deref(),
            base_role,
            body.description.as_deref(),
            body.priority,
            overrides_opt,
        )
        .await
        .map_err(map_service_error)?;
    if body.overrides.is_some() {
        record.overrides = overrides_vec;
    }
    Ok(Json(role_response_from(record)))
}

#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}/roles/{role_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("role_id" = Uuid, Path, description = "Role ID"),
    ),
    responses((status = 204))
)]
pub async fn delete_role(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path((workspace_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, crate::http::error::ApiError> {
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_UPDATE_ROLE).await?;
    ctx.workspace_service()
        .delete_role(workspace_id, role_id)
        .await
        .map_err(map_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}
