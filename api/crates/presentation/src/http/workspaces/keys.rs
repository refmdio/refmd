use axum::{extract::State, Json};
use uuid::Uuid;

use crate::context::WorkspacesContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::errors::ServiceError;

use super::types::{
    RotateWorkspaceKeyRequest, RotateWorkspaceKeyResponse, StoreWorkspaceKeyRequest,
    WorkspaceKeyResponse, WorkspaceKeyVersionResponse,
};

fn map_keys_error(err: ServiceError) -> ApiError {
    crate::http::error::map_service_error(err, "workspace_keys_service_error")
}

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/keys/me",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses(
        (status = 200, body = WorkspaceKeyResponse),
        (status = 404, description = "Key not found")
    )
)]
pub async fn get_my_workspace_key(
    State(ctx): State<WorkspacesContext>,
    auth: WorkspaceAuth,
) -> Result<Json<WorkspaceKeyResponse>, ApiError> {
    let service = ctx.workspace_keys_service();
    let dto = service
        .get_encrypted_kek(auth.workspace_id, auth.user_id)
        .await
        .map_err(map_keys_error)?
        .ok_or_else(|| ApiError::not_found("workspace_key_not_found"))?;

    Ok(Json(WorkspaceKeyResponse::from(dto)))
}

#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/keys",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    request_body = StoreWorkspaceKeyRequest,
    responses((status = 200, body = WorkspaceKeyResponse))
)]
pub async fn store_workspace_key(
    State(ctx): State<WorkspacesContext>,
    auth: WorkspaceAuth,
    axum::extract::Path(workspace_id): axum::extract::Path<Uuid>,
    Json(payload): Json<StoreWorkspaceKeyRequest>,
) -> Result<Json<WorkspaceKeyResponse>, ApiError> {
    // Verify the workspace_id matches the auth context
    if workspace_id != auth.workspace_id {
        return Err(ApiError::forbidden("workspace_mismatch"));
    }

    let encrypted_kek = payload
        .decode()
        .map_err(|e| ApiError::bad_request(e))?;

    let service = ctx.workspace_keys_service();
    let dto = service
        .store_encrypted_kek(
            auth.workspace_id,
            auth.user_id,
            encrypted_kek,
            payload.key_version,
        )
        .await
        .map_err(map_keys_error)?;

    Ok(Json(WorkspaceKeyResponse::from(dto)))
}

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/keys",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = Vec<WorkspaceKeyResponse>))
)]
pub async fn list_workspace_keys(
    State(ctx): State<WorkspacesContext>,
    auth: WorkspaceAuth,
) -> Result<Json<Vec<WorkspaceKeyResponse>>, ApiError> {
    // Check permission for listing all keys (admin operation)
    auth.ensure_permission("workspace:manage")?;

    let service = ctx.workspace_keys_service();
    let dtos = service
        .list_encrypted_keks(auth.workspace_id)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(dtos.into_iter().map(WorkspaceKeyResponse::from).collect()))
}

#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/keys/version",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    responses((status = 200, body = WorkspaceKeyVersionResponse))
)]
pub async fn get_workspace_key_version(
    State(ctx): State<WorkspacesContext>,
    auth: WorkspaceAuth,
) -> Result<Json<WorkspaceKeyVersionResponse>, ApiError> {
    let service = ctx.workspace_keys_service();
    let version = service
        .get_current_key_version(auth.workspace_id)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(WorkspaceKeyVersionResponse {
        workspace_id: auth.workspace_id,
        key_version: version,
    }))
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeleteKeyVersionResponse {
    pub workspace_id: Uuid,
    pub key_version: i32,
    pub deleted_count: u64,
}

#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}/keys/{version}",
    tag = "E2EE",
    params(
        ("id" = Uuid, Path, description = "Workspace ID"),
        ("version" = i32, Path, description = "Key version to delete")
    ),
    responses(
        (status = 200, body = DeleteKeyVersionResponse),
        (status = 403, description = "Permission denied")
    )
)]
pub async fn delete_key_version(
    State(ctx): State<WorkspacesContext>,
    auth: WorkspaceAuth,
    axum::extract::Path((workspace_id, key_version)): axum::extract::Path<(Uuid, i32)>,
) -> Result<Json<DeleteKeyVersionResponse>, ApiError> {
    // Verify the workspace_id matches the auth context
    if workspace_id != auth.workspace_id {
        return Err(ApiError::forbidden("workspace_mismatch"));
    }

    // Check permission for deleting keys (admin operation)
    auth.ensure_permission("workspace:manage")?;

    let service = ctx.workspace_keys_service();
    let deleted_count = service
        .delete_key_version(auth.workspace_id, key_version)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(DeleteKeyVersionResponse {
        workspace_id: auth.workspace_id,
        key_version,
        deleted_count,
    }))
}

#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/keys/rotate",
    tag = "E2EE",
    params(("id" = Uuid, Path, description = "Workspace ID")),
    request_body = RotateWorkspaceKeyRequest,
    responses(
        (status = 200, body = RotateWorkspaceKeyResponse),
        (status = 400, description = "Invalid request"),
        (status = 403, description = "Permission denied")
    )
)]
pub async fn rotate_workspace_key(
    State(ctx): State<WorkspacesContext>,
    auth: WorkspaceAuth,
    axum::extract::Path(workspace_id): axum::extract::Path<Uuid>,
    Json(payload): Json<RotateWorkspaceKeyRequest>,
) -> Result<Json<RotateWorkspaceKeyResponse>, ApiError> {
    // Verify the workspace_id matches the auth context
    if workspace_id != auth.workspace_id {
        return Err(ApiError::forbidden("workspace_mismatch"));
    }

    // Check permission for key rotation (admin operation)
    auth.ensure_permission("workspace:manage")?;

    let member_keys = payload
        .decode()
        .map_err(|e| ApiError::bad_request(e))?;

    let service = ctx.workspace_keys_service();
    let (new_version, keys_updated) = service
        .rotate_keys(auth.workspace_id, member_keys)
        .await
        .map_err(map_keys_error)?;

    Ok(Json(RotateWorkspaceKeyResponse {
        workspace_id: auth.workspace_id,
        new_key_version: new_version,
        keys_updated,
    }))
}
