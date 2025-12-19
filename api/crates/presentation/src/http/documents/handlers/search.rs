use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};

use crate::context::AppContext;
use crate::http::error::ApiError;
use crate::http::workspaces::scope as workspace_scope;
use crate::security::token::{self, Bearer};
use domain::access::permissions::PERM_DOC_VIEW;

use crate::http::documents::types::{SearchQuery, SearchResult, map_service_error};

#[utoipa::path(get, path = "/api/documents/search", tag = "Documents",
    params(("q" = Option<String>, Query, description = "Query")),
    responses((status = 200, body = [SearchResult])))]
pub async fn search_documents(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    q: Option<Query<SearchQuery>>,
) -> Result<Json<Vec<SearchResult>>, ApiError> {
    let bearer_token = bearer.0.clone();
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_DOC_VIEW)
        .await?;
    let query_text = q.and_then(|Query(v)| v.q);

    let service = ctx.document_service();
    let hits = service
        .search_for_user(workspace_id, query_text, 20)
        .await
        .map_err(map_service_error)?;
    let items = hits
        .into_iter()
        .map(|h| SearchResult {
            id: h.id,
            title: h.title.into_string(),
            document_type: h.doc_type.to_string(),
            path: h.path,
            updated_at: h.updated_at,
        })
        .collect();
    Ok(Json(items))
}
