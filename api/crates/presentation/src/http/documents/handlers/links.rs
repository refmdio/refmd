use axum::{
    Json,
    extract::{Path, State},
};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::access;
use domain::access::permissions::PERM_DOC_VIEW;

use crate::http::documents::types::{
    BacklinkInfo, BacklinksResponse, OutgoingLink, OutgoingLinksResponse, map_service_error,
};

#[utoipa::path(get, path = "/api/documents/{id}/backlinks", tag = "Documents", operation_id = "getBacklinks",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, body = BacklinksResponse)))]
pub async fn get_backlinks(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<BacklinksResponse>, ApiError> {
    auth.ensure_permission(PERM_DOC_VIEW)?;
    let actor = access::Actor::User(auth.user_id);
    let service = ctx.document_service();
    let items = service
        .backlinks(&actor, auth.workspace_id, id)
        .await
        .map_err(map_service_error)?;
    let backlinks: Vec<BacklinkInfo> = items
        .into_iter()
        .map(|r| BacklinkInfo {
            document_id: r.document_id.to_string(),
            title: r.title.into_string(),
            document_type: r.document_type.to_string(),
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
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<OutgoingLinksResponse>, ApiError> {
    auth.ensure_permission(PERM_DOC_VIEW)?;
    let actor = access::Actor::User(auth.user_id);
    let service = ctx.document_service();
    let items = service
        .outgoing_links(&actor, auth.workspace_id, id)
        .await
        .map_err(map_service_error)?;
    let links = items
        .into_iter()
        .map(|r| OutgoingLink {
            document_id: r.document_id.to_string(),
            title: r.title.into_string(),
            document_type: r.document_type.to_string(),
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
