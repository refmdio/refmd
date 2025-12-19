use axum::{
    Json,
    extract::{Query, State},
};

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::domain::access::permissions::PERM_DOC_VIEW;

use crate::http::documents::types::{SearchQuery, SearchResult, map_service_error};

#[utoipa::path(get, path = "/api/documents/search", tag = "Documents",
    params(("q" = Option<String>, Query, description = "Query")),
    responses((status = 200, body = [SearchResult])))]
pub async fn search_documents(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    q: Option<Query<SearchQuery>>,
) -> Result<Json<Vec<SearchResult>>, ApiError> {
    auth.ensure_permission(PERM_DOC_VIEW)?;
    let query_text = q.and_then(|Query(v)| v.q);

    let service = ctx.document_service();
    let hits = service
        .search_for_user(auth.workspace_id, query_text, 20)
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
