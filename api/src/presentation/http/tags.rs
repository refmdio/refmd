use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::get,
};
use serde::Serialize;
use tracing::error;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::dto::tags::TagItemDto;
use crate::application::services::errors::ServiceError;
use crate::presentation::context::AppContext;

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

fn map_tag_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            error!(error = ?inner, "tag_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
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
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let filter = q.and_then(|Query(m)| m.get("q").cloned());
    let service = ctx.tag_service();
    let items: Vec<TagItemDto> = service.list(user_id, filter).await.map_err(map_tag_error)?;
    let out: Vec<TagItem> = items.into_iter().map(Into::into).collect();
    Ok(Json(out))
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new().route("/tags", get(list_tags)).with_state(ctx)
}
