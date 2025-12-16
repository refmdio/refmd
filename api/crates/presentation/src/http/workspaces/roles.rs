use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use domain::workspaces::permissions::{
    PERM_MEMBER_INVITE, PERM_MEMBER_UPDATE_ROLE, PERM_MEMBER_VIEW,
};
use crate::context::AppContext;
use crate::http::auth::Bearer;

use super::types::{
    CreateWorkspaceRoleRequest, UpdateWorkspaceRoleRequest, WorkspaceRoleResponse,
    map_service_error, normalize_overrides, require_any_permission, require_permission,
    role_response_from, validate_base_role,
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
) -> Result<Json<Vec<WorkspaceRoleResponse>>, StatusCode> {
    let sub = crate::http::auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
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
) -> Result<Json<WorkspaceRoleResponse>, StatusCode> {
    if body.name.trim().is_empty() || !validate_base_role(body.base_role.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let overrides = normalize_overrides(body.overrides)?;
    let sub = crate::http::auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, id, user_id, PERM_MEMBER_UPDATE_ROLE).await?;
    let record = ctx
        .workspace_service()
        .create_role(
            id,
            user_id,
            body.name.trim(),
            body.base_role.trim(),
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
) -> Result<Json<WorkspaceRoleResponse>, StatusCode> {
    if let Some(base) = body.base_role.as_deref() {
        if !validate_base_role(base) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let overrides_vec = normalize_overrides(body.overrides.clone())?;
    let overrides_opt = if body.overrides.is_some() {
        Some(overrides_vec.as_slice())
    } else {
        None
    };
    let sub = crate::http::auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_UPDATE_ROLE).await?;
    let mut record = ctx
        .workspace_service()
        .update_role(
            workspace_id,
            user_id,
            role_id,
            body.name.as_deref(),
            body.base_role.as_deref(),
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
) -> Result<StatusCode, StatusCode> {
    let sub = crate::http::auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission(&ctx, workspace_id, user_id, PERM_MEMBER_UPDATE_ROLE).await?;
    ctx.workspace_service()
        .delete_role(workspace_id, role_id)
        .await
        .map_err(map_service_error)?;
    Ok(StatusCode::NO_CONTENT)
}
