use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::token::{self, Bearer};

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
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<CreateShareMountRequest>,
) -> Result<Json<ShareMountItem>, ApiError> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let service = ctx.share_service();
    let item = service
        .save_share_mount(
            workspace_id,
            user_id,
            &permissions,
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
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<Vec<ShareMountItem>>, ApiError> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let service = ctx.share_service();
    let items = service
        .list_share_mounts(workspace_id, &permissions)
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
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let service = ctx.share_service();
    let deleted = service
        .delete_share_mount(workspace_id, &permissions, id)
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
    bearer: Bearer,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<MaterializeResponse>, ApiError> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let service = ctx.share_service();
    let meta = service
        .share_document_meta(&token)
        .await
        .map_err(map_share_error)?
        .ok_or(ApiError::not_found("not_found"))?;
    if meta.workspace_id != workspace_id {
        return Err(ApiError::forbidden("forbidden"));
    }
    let actor = application::core::services::access::Actor::User(user_id);
    ctx.authorization()
        .require_edit(&actor, meta.document_id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;
    let created = service
        .materialize_folder_share(workspace_id, user_id, &permissions, &token)
        .await
        .map_err(map_share_error)?;
    Ok(Json(MaterializeResponse { created }))
}
