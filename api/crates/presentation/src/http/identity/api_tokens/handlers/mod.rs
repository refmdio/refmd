use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use crate::context::AppContext;
use crate::http::identity::auth::{self, Bearer};
use crate::http::workspaces::scope as workspace_scope;
use application::core::services::errors::ServiceError;

use super::types::{ApiTokenCreateRequest, ApiTokenCreateResponse, ApiTokenItem};

fn map_token_error(err: ServiceError) -> StatusCode {
    crate::http::error::map_service_error(err, "api_token_service_error")
}

#[utoipa::path(
    get,
    path = "/api/me/api-tokens",
    tag = "Auth",
    responses((status = 200, body = [ApiTokenItem]))
)]
pub async fn list_api_tokens(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<Vec<ApiTokenItem>>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = auth::validate_bearer(&ctx, Bearer(bearer_token.clone())).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;

    let service = ctx.api_token_service();
    let items = service
        .list(workspace_id, &permissions)
        .await
        .map_err(map_token_error)?;
    Ok(Json(items.into_iter().map(ApiTokenItem::from).collect()))
}

#[utoipa::path(
    post,
    path = "/api/me/api-tokens",
    tag = "Auth",
    request_body = ApiTokenCreateRequest,
    responses((status = 200, body = ApiTokenCreateResponse))
)]
pub async fn create_api_token(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(payload): Json<ApiTokenCreateRequest>,
) -> Result<Json<ApiTokenCreateResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = auth::validate_bearer(&ctx, Bearer(bearer_token.clone())).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;

    let service = ctx.api_token_service();
    let created = service
        .create(workspace_id, user_id, &permissions, payload.name.as_deref())
        .await
        .map_err(map_token_error)?;
    Ok(Json(ApiTokenCreateResponse::from(created)))
}

#[utoipa::path(
    delete,
    path = "/api/me/api-tokens/{id}",
    tag = "Auth",
    params(("id" = Uuid, Path, description = "Token ID")),
    responses((status = 204))
)]
pub async fn revoke_api_token(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = auth::validate_bearer(&ctx, Bearer(bearer_token.clone())).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;

    let service = ctx.api_token_service();
    let revoked = service
        .revoke(workspace_id, id, &permissions)
        .await
        .map_err(map_token_error)?;
    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
