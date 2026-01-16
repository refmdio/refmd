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

use super::types::{PublicDocumentSummary, PublicFile, PublishRequest, PublishResponse, UploadPublicFileRequest};

fn map_public_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "public_service_error")
}

#[utoipa::path(
    post,
    path = "/api/public/documents/{id}",
    tag = "Public Documents",
    params(("id" = Uuid, Path, description = "Document ID")),
    request_body(content = Option<PublishRequest>, description = "Optional plaintext content for E2EE workspaces"),
    responses((status = 200, description = "Published", body = PublishResponse))
)]
pub async fn publish_document(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
    body: Option<Json<PublishRequest>>,
) -> Result<Json<PublishResponse>, ApiError> {
    let (plaintext_title, plaintext_content) = body
        .map(|Json(req)| (req.plaintext_title, req.plaintext_content))
        .unwrap_or((None, None));

    let out = ctx
        .public_service()
        .publish_document(
            auth.workspace_id,
            &auth.permissions,
            id,
            plaintext_title.as_deref(),
            plaintext_content.as_deref(),
        )
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

// --- Public file endpoints ---

#[utoipa::path(
    post,
    path = "/api/public/documents/{id}/files/{file_id}",
    tag = "Public Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("file_id" = Uuid, Path, description = "File ID (original encrypted file ID)")
    ),
    request_body(content = UploadPublicFileRequest, description = "Decrypted file data"),
    responses((status = 204, description = "File uploaded"))
)]
pub async fn upload_public_file(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path((doc_id, file_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UploadPublicFileRequest>,
) -> Result<StatusCode, ApiError> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let bytes = STANDARD
        .decode(&req.content)
        .map_err(|_| ApiError::bad_request("invalid_base64"))?;

    ctx.public_service()
        .store_public_file(
            auth.workspace_id,
            &auth.permissions,
            doc_id,
            file_id,
            &req.original_filename,
            &req.logical_filename,
            &req.mime_type,
            &bytes,
        )
        .await
        .map_err(map_public_error)?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/public/workspaces/{slug}/{id}/files",
    tag = "Public Documents",
    params(
        ("slug" = String, Path, description = "Workspace slug"),
        ("id" = Uuid, Path, description = "Document ID")
    ),
    responses((status = 200, description = "List of public files", body = [PublicFile]))
)]
pub async fn list_public_files(
    State(ctx): State<DocumentsContext>,
    Path((slug, doc_id)): Path<(String, Uuid)>,
) -> Result<Json<Vec<PublicFile>>, ApiError> {
    let files = ctx
        .public_service()
        .get_public_files(&slug, doc_id)
        .await
        .map_err(map_public_error)?;

    Ok(Json(
        files
            .into_iter()
            .map(|f| PublicFile {
                id: f.id,
                file_id: f.file_id,
                original_filename: f.original_filename,
                logical_filename: f.logical_filename,
                mime_type: f.mime_type,
                size: f.size,
                created_at: f.created_at,
            })
            .collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/public/workspaces/{slug}/{id}/files/{filename}",
    tag = "Public Documents",
    params(
        ("slug" = String, Path, description = "Workspace slug"),
        ("id" = Uuid, Path, description = "Document ID"),
        ("filename" = String, Path, description = "Logical filename as it appears in markdown")
    ),
    responses(
        (status = 200, description = "File content", content_type = "application/octet-stream")
    )
)]
pub async fn get_public_file(
    State(ctx): State<DocumentsContext>,
    Path((slug, doc_id, filename)): Path<(String, Uuid, String)>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    use axum::http::header;

    let (bytes, meta) = ctx
        .public_service()
        .read_public_file_by_logical_filename(&slug, doc_id, &filename)
        .await
        .map_err(map_public_error)?;

    // Use inline disposition for images and other displayable content
    // so browsers can render them in <img> tags
    let content_disposition = format!("inline; filename=\"{}\"", meta.original_filename);

    Ok((
        [
            (header::CONTENT_TYPE, meta.mime_type),
            (header::CONTENT_DISPOSITION, content_disposition),
        ],
        bytes,
    ))
}
