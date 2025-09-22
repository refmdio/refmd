use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::get,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::dto::tags::TagItemDto;
use crate::application::use_cases::tags::list_tags::ListTags;
use crate::bootstrap::app_context::AppContext;

#[derive(Serialize, ToSchema)]
pub struct TagItem {
    pub name: String,
    pub count: i64,
}

impl From<TagItemDto> for TagItem {
    fn from(d: TagItemDto) -> Self {
        TagItem {
            name: d.name,
            count: d.count,
        }
    }
}

#[utoipa::path(get, path = "/api/tags", tag = "Tags",
    params(("q" = Option<String>, Query, description = "Filter contains")),
    responses((status = 200, body = [TagItem])))]
pub async fn list_tags(
    State(ctx): State<AppContext>,
    bearer: crate::presentation::http::auth::Bearer,
    q: Option<Query<std::collections::HashMap<String, String>>>,
) -> Result<Json<Vec<TagItem>>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let filter = q.and_then(|Query(m)| m.get("q").cloned());
    let repo = ctx.tag_repo();
    let uc = ListTags {
        repo: repo.as_ref(),
    };
    let items: Vec<TagItemDto> = uc
        .execute(user_id, filter)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let out: Vec<TagItem> = items.into_iter().map(Into::into).collect();
    Ok(Json(out))
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new().route("/tags", get(list_tags)).with_state(ctx)
}
