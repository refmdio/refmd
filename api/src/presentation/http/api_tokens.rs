use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
};
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::dto::api_tokens::{ApiTokenDto, CreatedApiTokenDto};
use crate::application::services::errors::ServiceError;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::{self, Bearer};

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiTokenItem {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<ApiTokenDto> for ApiTokenItem {
    fn from(value: ApiTokenDto) -> Self {
        Self {
            id: value.id,
            name: value.name,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
            revoked_at: value.revoked_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiTokenCreateResponse {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub token: String,
}

impl From<CreatedApiTokenDto> for ApiTokenCreateResponse {
    fn from(value: CreatedApiTokenDto) -> Self {
        Self {
            id: value.token.id,
            name: value.token.name,
            created_at: value.token.created_at,
            token: value.plaintext,
        }
    }
}

fn map_token_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            error!(error = ?inner, "api_token_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ApiTokenCreateRequest {
    #[schema(example = "Deploy token")]
    pub name: Option<String>,
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
) -> Result<Json<Vec<ApiTokenItem>>, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let service = ctx.api_token_service();
    let items = service.list(user_id).await.map_err(map_token_error)?;
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
    Json(payload): Json<ApiTokenCreateRequest>,
) -> Result<Json<ApiTokenCreateResponse>, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let service = ctx.api_token_service();
    let created = service
        .create(user_id, payload.name.as_deref())
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
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let service = ctx.api_token_service();
    let revoked = service.revoke(user_id, id).await.map_err(map_token_error)?;
    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/me/api-tokens",
            get(list_api_tokens).post(create_api_token),
        )
        .route("/me/api-tokens/:id", delete(revoke_api_token))
        .with_state(ctx)
}
