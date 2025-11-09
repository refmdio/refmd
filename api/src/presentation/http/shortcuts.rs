use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::dto::user_shortcuts::UserShortcutProfileDto;
use crate::application::services::errors::ServiceError;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::{self, Bearer};
use tracing::error;

#[derive(Debug, Serialize, ToSchema)]
pub struct UserShortcutResponse {
    #[schema(value_type = Object)]
    pub bindings: Value,
    #[schema(example = "<Space>")]
    pub leader_key: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl UserShortcutResponse {
    fn empty() -> Self {
        Self {
            bindings: Value::Object(Map::new()),
            leader_key: None,
            updated_at: None,
        }
    }
}

impl From<UserShortcutProfileDto> for UserShortcutResponse {
    fn from(value: UserShortcutProfileDto) -> Self {
        Self {
            bindings: value.bindings,
            leader_key: value.leader_key,
            updated_at: Some(value.updated_at),
        }
    }
}

fn map_shortcut_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            error!(error = ?inner, "user_shortcut_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserShortcutRequest {
    #[schema(value_type = Object)]
    #[serde(default = "Value::default")]
    pub bindings: Value,
    #[schema(example = "<Space>")]
    pub leader_key: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/me/shortcuts",
    tag = "Auth",
    responses((status = 200, body = UserShortcutResponse))
)]
pub async fn get_user_shortcuts(
    State(ctx): State<AppContext>,
    bearer: Bearer,
) -> Result<Json<UserShortcutResponse>, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let service = ctx.user_shortcut_service();
    let profile = service
        .get_profile(user_id)
        .await
        .map_err(map_shortcut_error)?;
    let response = profile
        .map(UserShortcutResponse::from)
        .unwrap_or_else(UserShortcutResponse::empty);
    Ok(Json(response))
}

#[utoipa::path(
    put,
    path = "/api/me/shortcuts",
    tag = "Auth",
    request_body = UpdateUserShortcutRequest,
    responses((status = 200, body = UserShortcutResponse))
)]
pub async fn update_user_shortcuts(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Json(payload): Json<UpdateUserShortcutRequest>,
) -> Result<Json<UserShortcutResponse>, StatusCode> {
    let sub = auth::validate_bearer(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let service = ctx.user_shortcut_service();
    let result = service
        .update_profile(user_id, payload.bindings, payload.leader_key)
        .await
        .map_err(map_shortcut_error)?;
    Ok(Json(UserShortcutResponse::from(result)))
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/me/shortcuts",
            get(get_user_shortcuts).put(update_user_shortcuts),
        )
        .with_state(ctx)
}
