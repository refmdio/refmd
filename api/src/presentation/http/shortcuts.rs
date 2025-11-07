use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::use_cases::user_shortcuts::get_shortcuts::GetUserShortcuts;
use crate::application::use_cases::user_shortcuts::update_shortcuts::{
    UpdateUserShortcuts, UpdateUserShortcutsPayload,
};
use crate::bootstrap::app_context::AppContext;
use crate::presentation::http::auth::{self, Bearer};

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

impl From<crate::application::ports::user_shortcut_repository::UserShortcutProfile>
    for UserShortcutResponse
{
    fn from(
        value: crate::application::ports::user_shortcut_repository::UserShortcutProfile,
    ) -> Self {
        Self {
            bindings: value.bindings,
            leader_key: value.leader_key,
            updated_at: Some(value.updated_at),
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
    let repo = ctx.user_shortcuts();
    let uc = GetUserShortcuts {
        repo: repo.as_ref(),
    };
    let profile = uc
        .execute(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    let repo = ctx.user_shortcuts();
    let uc = UpdateUserShortcuts {
        repo: repo.as_ref(),
        max_payload_bytes: 32 * 1024,
    };
    let result = uc
        .execute(
            user_id,
            UpdateUserShortcutsPayload {
                bindings: payload.bindings,
                leader_key: payload.leader_key,
            },
        )
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
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
