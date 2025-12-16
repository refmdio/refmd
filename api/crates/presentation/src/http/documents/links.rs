use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use application::access;
use domain::workspaces::permissions::PERM_DOC_VIEW;
use crate::context::AppContext;
use crate::http::auth::Bearer;
use crate::http::workspaces::scope as workspace_scope;

use super::types::{
    BacklinkInfo, BacklinksResponse, OutgoingLink, OutgoingLinksResponse, map_service_error,
};

#[utoipa::path(get, path = "/api/documents/{id}/backlinks", tag = "Documents", operation_id = "getBacklinks",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, body = BacklinksResponse)))]
pub async fn get_backlinks(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<BacklinksResponse>, StatusCode> {
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
    let actor = access::Actor::User(user_id);
    let service = ctx.document_service();
    let items = service
        .backlinks(&actor, workspace_id, id)
        .await
        .map_err(map_service_error)?;
    let backlinks: Vec<BacklinkInfo> = items
        .into_iter()
        .map(|r| BacklinkInfo {
            document_id: r.document_id.to_string(),
            title: r.title,
            document_type: r.document_type,
            file_path: r.file_path,
            link_type: r.link_type,
            link_text: r.link_text,
            link_count: r.link_count,
        })
        .collect();
    Ok(Json(BacklinksResponse {
        total_count: backlinks.len(),
        backlinks,
    }))
}

#[utoipa::path(get, path = "/api/documents/{id}/links", tag = "Documents", operation_id = "getOutgoingLinks",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, body = OutgoingLinksResponse)))]
pub async fn get_outgoing_links(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<OutgoingLinksResponse>, StatusCode> {
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
    let actor = access::Actor::User(user_id);
    let service = ctx.document_service();
    let items = service
        .outgoing_links(&actor, workspace_id, id)
        .await
        .map_err(map_service_error)?;
    let links = items
        .into_iter()
        .map(|r| OutgoingLink {
            document_id: r.document_id.to_string(),
            title: r.title,
            document_type: r.document_type,
            file_path: r.file_path,
            link_type: r.link_type,
            link_text: r.link_text,
            position_start: r.position_start,
            position_end: r.position_end,
        })
        .collect::<Vec<_>>();

    Ok(Json(OutgoingLinksResponse {
        total_count: links.len(),
        links,
    }))
}
