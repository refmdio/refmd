use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::documents::{Document, to_http_document};
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use application::core::services::errors::ServiceError;

use super::types::{PublicDocumentSummary, PublishResponse};

fn map_public_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "public_service_error")
}

#[utoipa::path(
    post,
    path = "/api/public/documents/{id}",
    tag = "Public Documents",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, description = "Published", body = PublishResponse))
)]
pub async fn publish_document(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<PublishResponse>, ApiError> {
    let service = ctx.public_service();
    let out = service
        .publish_document(auth.workspace_id, &auth.permissions, id)
        .await
        .map_err(map_public_error)?;
    Ok(Json(PublishResponse {
        slug: out.slug,
        public_url: out.public_url,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/public/documents/{id}",
    tag = "Public Documents",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 204, description = "Unpublished"))
)]
pub async fn unpublish_document(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let ok = ctx
        .public_service()
        .unpublish_document(auth.workspace_id, &auth.permissions, id)
        .await
        .map_err(map_public_error)?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::forbidden("forbidden"))
    }
}

#[utoipa::path(
    get,
    path = "/api/public/documents/{id}",
    tag = "Public Documents",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, description = "Published status", body = PublishResponse))
)]
pub async fn get_publish_status(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<PublishResponse>, ApiError> {
    let out = ctx
        .public_service()
        .get_publish_status(auth.workspace_id, &auth.permissions, id)
        .await
        .map_err(map_public_error)?;
    Ok(Json(PublishResponse {
        slug: out.slug,
        public_url: out.public_url,
    }))
}

// Slug-based endpoints are intentionally omitted to simplify routing and match legacy pattern strictly.

#[utoipa::path(
    get,
    path = "/api/public/workspaces/{slug}",
    tag = "Public Documents",
    params(("slug" = String, Path, description = "Workspace slug")),
    responses((status = 200, description = "Public documents for workspace", body = [PublicDocumentSummary]))
)]
pub async fn list_workspace_public_documents(
    State(ctx): State<DocumentsContext>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<PublicDocumentSummary>>, ApiError> {
    let items = ctx
        .public_service()
        .list_workspace_public_documents(&slug)
        .await
        .map_err(map_public_error)?;
    Ok(Json(
        items.into_iter().map(PublicDocumentSummary::from).collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/public/workspaces/{slug}/{id}",
    tag = "Public Documents",
    params(("slug" = String, Path, description = "Workspace slug"), ("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, description = "Document metadata", body = Document))
)]
pub async fn get_public_by_workspace_and_id(
    State(ctx): State<DocumentsContext>,
    Path((slug, id)): Path<(String, Uuid)>,
) -> Result<Json<Document>, ApiError> {
    let doc = ctx
        .public_service()
        .get_public_by_workspace_and_id(&slug, id)
        .await
        .map_err(map_public_error)?;
    Ok(Json(to_http_document(doc)))
}

#[utoipa::path(
    get,
    path = "/api/public/workspaces/{slug}/{id}/content",
    tag = "Public Documents",
    params(("slug" = String, Path, description = "Workspace slug"), ("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, description = "Document content"))
)]
pub async fn get_public_content_by_workspace_and_id(
    State(ctx): State<DocumentsContext>,
    Path((slug, id)): Path<(String, Uuid)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let content = ctx
        .public_service()
        .get_public_content_by_workspace_and_id(&slug, id)
        .await
        .map_err(map_public_error)?;
    Ok(Json(serde_json::json!({"content": content, "id": id})))
}
