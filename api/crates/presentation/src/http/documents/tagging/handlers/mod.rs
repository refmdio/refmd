use axum::{
    Json,
    extract::{Query, State},
};

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::errors::ServiceError;
use domain::access::permissions::PERM_DOC_VIEW;

use super::types::TagItem;

fn map_tag_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "tag_service_error")
}

#[utoipa::path(get, path = "/api/tags", tag = "Tags",
    params(("q" = Option<String>, Query, description = "Filter contains")),
    responses((status = 200, body = [TagItem])))]
pub async fn list_tags(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    q: Option<Query<std::collections::HashMap<String, String>>>,
) -> Result<Json<Vec<TagItem>>, ApiError> {
    auth.ensure_permission(PERM_DOC_VIEW)?;
    let filter = q.and_then(|Query(m)| m.get("q").cloned());
    let service = ctx.tag_service();
    let items = service
        .list(auth.workspace_id, filter)
        .await
        .map_err(map_tag_error)?;
    let out: Vec<TagItem> = items.into_iter().map(Into::into).collect();
    Ok(Json(out))
}
