use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;

use super::types::{CreateShareMountRequest, MaterializeResponse, ShareMountItem, map_share_error};

#[utoipa::path(
    post,
    path = "/api/shares/mounts",
    tag = "Sharing",
    request_body = CreateShareMountRequest,
    responses((status = 200, description = "Saved share mount", body = ShareMountItem))
)]
pub async fn create_share_mount(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Json(req): Json<CreateShareMountRequest>,
) -> Result<Json<ShareMountItem>, ApiError> {
    let service = ctx.share_service();
    let item = service
        .save_share_mount(
            auth.workspace_id,
            auth.user_id,
            &auth.permissions,
            &req.token,
            req.parent_folder_id,
        )
        .await
        .map_err(map_share_error)?;
    Ok(Json(item.into()))
}

#[utoipa::path(
    get,
    path = "/api/shares/mounts",
    tag = "Sharing",
    responses((status = 200, description = "Share mounts", body = [ShareMountItem]))
)]
pub async fn list_share_mounts(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
) -> Result<Json<Vec<ShareMountItem>>, ApiError> {
    let service = ctx.share_service();
    let items = service
        .list_share_mounts(auth.workspace_id, &auth.permissions)
        .await
        .map_err(map_share_error)?;
    Ok(Json(items.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    delete,
    path = "/api/shares/mounts/{id}",
    tag = "Sharing",
    params(("id" = Uuid, Path, description = "Share mount ID")),
    responses((status = 204, description = "Share mount removed"))
)]
pub async fn delete_share_mount(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let service = ctx.share_service();
    let deleted = service
        .delete_share_mount(auth.workspace_id, &auth.permissions, id)
        .await
        .map_err(map_share_error)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("not_found"))
    }
}

#[utoipa::path(post, path = "/api/shares/folders/{token}/materialize", tag = "Sharing",
    params(("token" = String, Path, description = "Folder share token")),
    responses((status = 200, description = "Created doc shares", body = MaterializeResponse))
)]
pub async fn materialize_folder_share(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(token): Path<String>,
) -> Result<Json<MaterializeResponse>, ApiError> {
    let service = ctx.share_service();
    let meta = service
        .share_document_meta(&token)
        .await
        .map_err(map_share_error)?
        .ok_or(ApiError::not_found("not_found"))?;
    if meta.workspace_id != auth.workspace_id {
        return Err(ApiError::forbidden("forbidden"));
    }
    let actor = application::core::services::access::Actor::User(auth.user_id);
    ctx.authorization()
        .require_edit(&actor, meta.document_id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;
    let created = service
        .materialize_folder_share(auth.workspace_id, auth.user_id, &auth.permissions, &token)
        .await
        .map_err(map_share_error)?;
    Ok(Json(MaterializeResponse { created }))
}
