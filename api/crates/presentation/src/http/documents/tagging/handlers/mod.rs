use axum::{
    Json,
    extract::{Path, Query, State},
};
use base64::Engine;
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::access;
use application::core::services::errors::ServiceError;
use domain::access::permissions::{PERM_DOC_EDIT, PERM_DOC_VIEW};

use super::types::{
    DocumentTagEntry, DocumentTagsResponse, ListTagsResponse, TagEntry, TagSearchQuery,
    UpdateDocumentTagsRequest,
};

fn map_tag_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "tag_service_error")
}

/// List all tags in the workspace (E2EE format)
#[utoipa::path(
    get,
    path = "/api/tags",
    tag = "Tags",
    params(("q" = Option<String>, Query, description = "Base64 encoded encrypted tag for exact match filter")),
    responses((status = 200, body = ListTagsResponse))
)]
pub async fn list_tags(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Query(query): Query<TagSearchQuery>,
) -> Result<Json<ListTagsResponse>, ApiError> {
    auth.ensure_permission(PERM_DOC_VIEW)?;

    let service = ctx.tag_service();

    // If filter is provided, decode and use it for exact match
    let items = if let Some(q) = query.q {
        let encrypted_tag = base64::engine::general_purpose::STANDARD
            .decode(&q)
            .map_err(|_| ApiError::bad_request("invalid_encrypted_tag_base64"))?;
        service
            .find_encrypted_tag(auth.workspace_id, encrypted_tag)
            .await
            .map_err(map_tag_error)?
    } else {
        service
            .list_encrypted_tags(auth.workspace_id)
            .await
            .map_err(map_tag_error)?
    };

    let tags: Vec<TagEntry> = items.into_iter().map(Into::into).collect();
    Ok(Json(ListTagsResponse { tags }))
}

/// Get tags for a specific document (E2EE format)
#[utoipa::path(
    get,
    path = "/api/documents/{id}/tags",
    tag = "Tags",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, body = DocumentTagsResponse))
)]
pub async fn get_document_tags(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<DocumentTagsResponse>, ApiError> {
    let actor = access::Actor::User(auth.user_id);
    ctx.authorization()
        .require_view(&actor, id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;

    let service = ctx.tag_service();
    let items = service
        .list_document_encrypted_tags(id)
        .await
        .map_err(map_tag_error)?;
    let tags: Vec<DocumentTagEntry> = items.into_iter().map(Into::into).collect();
    Ok(Json(DocumentTagsResponse { tags }))
}

/// Replace tags for a document (E2EE format)
#[utoipa::path(
    put,
    path = "/api/documents/{id}/tags",
    tag = "Tags",
    params(("id" = Uuid, Path, description = "Document ID")),
    request_body = UpdateDocumentTagsRequest,
    responses((status = 200, body = DocumentTagsResponse))
)]
pub async fn update_document_tags(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateDocumentTagsRequest>,
) -> Result<Json<DocumentTagsResponse>, ApiError> {
    auth.ensure_permission(PERM_DOC_EDIT)?;
    let actor = access::Actor::User(auth.user_id);
    ctx.authorization()
        .require_edit(&actor, id)
        .await
        .map_err(|err| crate::http::error::map_service_error(err, "authorization_error"))?;

    // Decode Base64 encoded tags
    let encrypted_tags: Vec<Vec<u8>> = req
        .encrypted_tags
        .iter()
        .map(|t| {
            base64::engine::general_purpose::STANDARD
                .decode(&t.encrypted_name)
                .map_err(|_| ApiError::bad_request("invalid_encrypted_tag_base64"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let service = ctx.tag_service();
    let items = service
        .replace_document_encrypted_tags(auth.workspace_id, id, encrypted_tags)
        .await
        .map_err(map_tag_error)?;
    let tags: Vec<DocumentTagEntry> = items.into_iter().map(Into::into).collect();
    Ok(Json(DocumentTagsResponse { tags }))
}
