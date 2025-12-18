use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use tracing::error;

use crate::context::AppContext;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::token::{self, Bearer};
use application::core::services::errors::ServiceError;
use domain::access::permissions::PERM_DOC_VIEW;

use super::types::TagItem;

fn map_tag_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized | ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
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
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id =
        workspace_scope::resolve_active_workspace_id(&ctx, &headers, None, user_id).await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_DOC_VIEW)
        .await?;
    let filter = q.and_then(|Query(m)| m.get("q").cloned());
    let service = ctx.tag_service();
    let items = service
        .list(workspace_id, filter)
        .await
        .map_err(map_tag_error)?;
    let out: Vec<TagItem> = items.into_iter().map(Into::into).collect();
    Ok(Json(out))
}
