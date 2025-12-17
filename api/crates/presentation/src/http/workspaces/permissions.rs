use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::context::AppContext;
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkspacePermissionsResponse>, StatusCode> {
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let set = ctx
        .workspace_service()
        .resolve_permission_set(id, user_id)
        .await
        .map_err(map_service_error)?
        .ok_or(StatusCode::FORBIDDEN)?;
    Ok(Json(WorkspacePermissionsResponse {
        workspace_id: id,
        permissions: set.to_vec(),
    }))
}
