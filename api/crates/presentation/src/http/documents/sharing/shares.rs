use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::access;
use domain::documents::share::SHARE_PERMISSION_VIEW;

use application::documents::dtos::ShareItemDto;

use super::types::{
    CreateShareRequest, CreateShareResponse, ShareItem, build_share_url, frontend_base,
    map_share_error,
};

#[utoipa::path(
    post,
    path = "/api/shares",
    tag = "Sharing",
    request_body = CreateShareRequest,
    responses((status = 200, description = "Share link created", body = CreateShareResponse))
)]
pub async fn create_share(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Json(req): Json<CreateShareRequest>,
) -> Result<Json<CreateShareResponse>, ApiError> {
    let actor = access::Actor::User(auth.user_id);
    ctx.authorization()
        .require_edit(&actor, req.document_id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;
    let permission = req.permission.as_deref().unwrap_or(SHARE_PERMISSION_VIEW);
    let service = ctx.share_service();
    let res = service
        .create_share(
            auth.workspace_id,
            auth.user_id,
            &auth.permissions,
            req.document_id,
            permission,
            req.expires_at,
        )
        .await
        .map_err(map_share_error)?;
    let base = frontend_base(&ctx.cfg);
    let url = build_share_url(&base, &res.document_type, res.document_id, &res.token);
    Ok(Json(CreateShareResponse {
        token: res.token,
        url,
    }))
}

#[utoipa::path(
    get,
    path = "/api/shares/documents/{id}",
    tag = "Sharing",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, description = "OK", body = [ShareItem]))
)]
pub async fn list_document_shares(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ShareItem>>, ApiError> {
    let actor = access::Actor::User(auth.user_id);
    ctx.authorization()
        .require_edit(&actor, id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;
    let service = ctx.share_service();
    let rows: Vec<ShareItemDto> = service
        .list_document_shares(auth.workspace_id, &auth.permissions, id)
        .await
        .map_err(map_share_error)?;
    let base = frontend_base(&ctx.cfg);
    let items: Vec<ShareItem> = rows
        .into_iter()
        .map(|r| ShareItem::from_dto(&base, r))
        .collect();
    Ok(Json(items))
}

#[utoipa::path(
    delete,
    path = "/api/shares/{token}",
    tag = "Sharing",
    params(("token" = String, Path, description = "Share token")),
    responses((status = 204, description = "Share link deleted"))
)]
pub async fn delete_share(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(token): Path<String>,
) -> Result<StatusCode, ApiError> {
    let service = ctx.share_service();
    let meta = service
        .share_document_meta(&token)
        .await
        .map_err(map_share_error)?
        .ok_or(ApiError::not_found("not_found"))?;
    if meta.workspace_id != auth.workspace_id {
        return Err(ApiError::forbidden("forbidden"));
    }
    let actor = access::Actor::User(auth.user_id);
    ctx.authorization()
        .require_edit(&actor, meta.document_id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;
    let ok = service
        .delete_share(auth.workspace_id, &auth.permissions, &token)
        .await
        .map_err(map_share_error)?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("not_found"))
    }
}
