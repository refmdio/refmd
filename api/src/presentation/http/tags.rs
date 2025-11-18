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
use crate::application::services::workspaces::permissions::PERM_DOC_VIEW;
use crate::presentation::context::AppContext;
use crate::presentation::http::{
    auth::{self, Bearer},
    workspace_scope,
};

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
    bearer: Bearer,
    headers: axum::http::HeaderMap,
    q: Option<Query<std::collections::HashMap<String, String>>>,
) -> Result<Json<Vec<TagItem>>, StatusCode> {
    let sub = auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id =
        workspace_scope::resolve_active_workspace_id(&ctx, &headers, None, user_id).await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_DOC_VIEW)
        .await?;
    let filter = q.and_then(|Query(m)| m.get("q").cloned());
    let service = ctx.tag_service();
    let items: Vec<TagItemDto> = service
        .list(workspace_id, filter)
        .await
        .map_err(map_tag_error)?;
    let out: Vec<TagItem> = items.into_iter().map(Into::into).collect();
    Ok(Json(out))
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new().route("/tags", get(list_tags)).with_state(ctx)
}
