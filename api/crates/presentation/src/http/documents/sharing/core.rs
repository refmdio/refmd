use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use application::core::services::access;
use crate::context::AppContext;
use crate::security::token::{self, Bearer};
use crate::http::workspaces::scope as workspace_scope;

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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<CreateShareRequest>,
) -> Result<Json<CreateShareResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let actor = access::Actor::User(user_id);
    ctx.authorization()
        .require_edit(&actor, req.document_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let permission = req.permission.as_deref().unwrap_or("view");
    let service = ctx.share_service();
    let res = service
        .create_share(
            workspace_id,
            user_id,
            &permissions,
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ShareItem>>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let actor = access::Actor::User(user_id);
    ctx.authorization()
        .require_edit(&actor, id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let service = ctx.share_service();
    let rows: Vec<ShareItemDto> = service
        .list_document_shares(workspace_id, &permissions, id)
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
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
        .ok_or(StatusCode::NOT_FOUND)?;
    if meta.workspace_id != workspace_id {
        return Err(StatusCode::FORBIDDEN);
    }
    let actor = access::Actor::User(user_id);
    ctx.authorization()
        .require_edit(&actor, meta.document_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let ok = service
        .delete_share(workspace_id, &permissions, &token)
        .await
        .map_err(map_share_error)?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
