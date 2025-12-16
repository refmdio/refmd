use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use domain::workspaces::permissions::PERM_DOC_VIEW;
use crate::context::AppContext;
use crate::http::auth::Bearer;
use crate::http::workspaces::scope as workspace_scope;

use super::types::{SearchQuery, SearchResult, map_service_error};

#[utoipa::path(get, path = "/api/documents/search", tag = "Documents",
    params(("q" = Option<String>, Query, description = "Query")),
    responses((status = 200, body = [SearchResult])))]
pub async fn search_documents(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    q: Option<Query<SearchQuery>>,
) -> Result<Json<Vec<SearchResult>>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = crate::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
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
            title: h.title,
            document_type: h.doc_type,
            path: h.path,
            updated_at: h.updated_at,
        })
        .collect();
    Ok(Json(items))
}
