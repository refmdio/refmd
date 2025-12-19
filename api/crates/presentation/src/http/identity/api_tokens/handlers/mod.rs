use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::context::IdentityContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::errors::ServiceError;

use super::types::{ApiTokenCreateRequest, ApiTokenCreateResponse, ApiTokenItem};

fn map_token_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "api_token_service_error")
}

#[utoipa::path(
    get,
    path = "/api/me/api-tokens",
    tag = "Auth",
    responses((status = 200, body = [ApiTokenItem]))
)]
pub async fn list_api_tokens(
    State(ctx): State<IdentityContext>,
    auth: WorkspaceAuth,
) -> Result<Json<Vec<ApiTokenItem>>, ApiError> {
    let service = ctx.api_token_service();
    let items = service
        .list(auth.workspace_id, &auth.permissions)
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
    State(ctx): State<IdentityContext>,
    auth: WorkspaceAuth,
    Json(payload): Json<ApiTokenCreateRequest>,
) -> Result<Json<ApiTokenCreateResponse>, ApiError> {
    let service = ctx.api_token_service();
    let created = service
        .create(
            auth.workspace_id,
            auth.user_id,
            &auth.permissions,
            payload.name.as_deref(),
        )
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
    State(ctx): State<IdentityContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let service = ctx.api_token_service();
    let revoked = service
        .revoke(auth.workspace_id, id, &auth.permissions)
        .await
        .map_err(map_token_error)?;
    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("not_found"))
    }
}
