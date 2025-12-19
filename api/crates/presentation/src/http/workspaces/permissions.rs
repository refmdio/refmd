use axum::{
    Json,
    extract::{Path, State},
};
use uuid::Uuid;

use crate::context::WorkspacesContext;
use crate::security::token::{self, Bearer};

use super::types::{WorkspacePermissionsResponse, map_service_error};

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/permissions",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = WorkspacePermissionsResponse))
)]
pub async fn get_workspace_permissions(
    State(ctx): State<WorkspacesContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkspacePermissionsResponse>, crate::http::error::ApiError> {
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    let set = ctx
        .workspace_service()
        .resolve_permission_set(id, user_id)
        .await
        .map_err(map_service_error)?
        .ok_or(crate::http::error::ApiError::forbidden("forbidden"))?;
    Ok(Json(WorkspacePermissionsResponse {
        workspace_id: id,
        permissions: set.to_vec(),
    }))
}
