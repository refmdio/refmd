use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::access;
use crate::application::dto::diff::TextDiffResult;
use crate::application::dto::document_export::DocumentDownloadFormat;
use crate::application::dto::documents::{
    DocumentListFilter, SnapshotDiffBaseMode, SnapshotDiffSideDto, SnapshotSummaryDto,
};
use crate::application::services::documents::DocumentPatchOperation;
use crate::application::services::errors::ServiceError;
use crate::domain::documents::document as domain;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::{self, Bearer};
use tracing::error;

#[derive(Debug, Serialize, ToSchema)]
pub struct Document {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub title: String,
    pub parent_id: Option<Uuid>,
    pub r#type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub slug: String,
    pub desired_path: String,
    pub path: Option<String>,
    pub archived_at: Option<chrono::DateTime<chrono::Utc>>,
    pub archived_by: Option<Uuid>,
    pub archived_parent_id: Option<Uuid>,
}

fn to_http_document(doc: domain::Document) -> Document {
    Document {
        id: doc.id,
        owner_id: doc.owner_id,
        title: doc.title,
        parent_id: doc.parent_id,
        r#type: doc.doc_type,
        created_at: doc.created_at,
        updated_at: doc.updated_at,
        slug: doc.slug,
        desired_path: doc.desired_path,
        path: doc.path,
        archived_at: doc.archived_at,
        archived_by: doc.archived_by,
        archived_parent_id: doc.archived_parent_id,
    }
}

fn map_service_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            error!(error = ?inner, "document_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentListResponse {
    pub items: Vec<Document>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SnapshotSummary {
    pub id: Uuid,
    pub document_id: Uuid,
    pub label: String,
    pub notes: Option<String>,
    pub kind: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Option<Uuid>,
    pub byte_size: i64,
    pub content_hash: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SnapshotListResponse {
    pub items: Vec<SnapshotSummary>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotDiffKind {
    Current,
    Snapshot,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SnapshotDiffSideResponse {
    pub kind: SnapshotDiffKind,
    pub markdown: String,
    pub snapshot: Option<SnapshotSummary>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SnapshotDiffResponse {
    pub base: SnapshotDiffSideResponse,
    pub target: SnapshotDiffSideResponse,
    pub diff: TextDiffResult,
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotDiffBaseParam {
    Auto,
    Current,
    Previous,
}

impl Default for SnapshotDiffBaseParam {
    fn default() -> Self {
        Self::Auto
    }
}

impl From<SnapshotDiffBaseParam> for SnapshotDiffBaseMode {
    fn from(value: SnapshotDiffBaseParam) -> Self {
        match value {
            SnapshotDiffBaseParam::Auto => SnapshotDiffBaseMode::Auto,
            SnapshotDiffBaseParam::Current => SnapshotDiffBaseMode::ForceCurrent,
            SnapshotDiffBaseParam::Previous => SnapshotDiffBaseMode::ForcePrevious,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SnapshotRestoreResponse {
    pub snapshot: SnapshotSummary,
}

fn snapshot_summary_from(record: SnapshotSummaryDto) -> SnapshotSummary {
    SnapshotSummary {
        id: record.id,
        document_id: record.document_id,
        label: record.label,
        notes: record.notes,
        kind: record.kind,
        created_at: record.created_at,
        created_by: record.created_by,
        byte_size: record.byte_size,
        content_hash: record.content_hash,
    }
}

fn snapshot_diff_side_response_from(side: SnapshotDiffSideDto) -> SnapshotDiffSideResponse {
    match side {
        SnapshotDiffSideDto::Current { markdown } => SnapshotDiffSideResponse {
            kind: SnapshotDiffKind::Current,
            markdown,
            snapshot: None,
        },
        SnapshotDiffSideDto::Snapshot { snapshot, markdown } => SnapshotDiffSideResponse {
            kind: SnapshotDiffKind::Snapshot,
            markdown,
            snapshot: Some(snapshot_summary_from(snapshot)),
        },
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDocumentRequest {
    pub title: Option<String>,
    pub parent_id: Option<Uuid>,
    pub r#type: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateDocumentRequest {
    pub title: Option<String>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    #[schema(value_type = Option<String>)]
    pub parent_id: DoubleOption<Uuid>,
}

impl Default for UpdateDocumentRequest {
    fn default() -> Self {
        Self {
            title: None,
            parent_id: DoubleOption::NotProvided,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DoubleOption<T> {
    NotProvided,
    Null,
    Some(T),
}

fn deserialize_double_option<'de, D, T>(deserializer: D) -> Result<DoubleOption<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(|opt| match opt {
        None => DoubleOption::Null,
        Some(value) => DoubleOption::Some(value),
    })
}

impl<T> Default for DoubleOption<T> {
    fn default() -> Self {
        DoubleOption::NotProvided
    }
}

// Uses AppContext as router state

#[derive(Debug, Deserialize)]
pub struct ListDocumentsQuery {
    pub query: Option<String>,
    pub tag: Option<String>,
    #[serde(default)]
    pub state: Option<DocumentStateFilter>,
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DocumentStateFilter {
    Active,
    Archived,
    All,
}

impl From<DocumentStateFilter> for DocumentListFilter {
    fn from(value: DocumentStateFilter) -> Self {
        match value {
            DocumentStateFilter::Active => DocumentListFilter::Active,
            DocumentStateFilter::Archived => DocumentListFilter::Archived,
            DocumentStateFilter::All => DocumentListFilter::All,
        }
    }
}

#[utoipa::path(get, path = "/api/documents", tag = "Documents",
    params(
        ("query" = Option<String>, Query, description = "Search query"),
        ("tag" = Option<String>, Query, description = "Filter by tag"),
        ("state" = Option<String>, Query, description = "Filter by document state (active|archived|all)")
    ),
    responses((status = 200, body = DocumentListResponse)))]
pub async fn list_documents(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    q: Option<Query<ListDocumentsQuery>>,
) -> Result<Json<DocumentListResponse>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let (qstr, tag, state_param) = q
        .map(|Query(v)| (v.query, v.tag, v.state))
        .unwrap_or((None, None, None));
    let state = state_param
        .map(DocumentStateFilter::into)
        .unwrap_or_default();

    let service = ctx.document_service();
    let docs = service
        .list_for_user(user_id, qstr, tag, state)
        .await
        .map_err(map_service_error)?;

    let items: Vec<Document> = docs.into_iter().map(to_http_document).collect();
    Ok(Json(DocumentListResponse { items }))
}

#[utoipa::path(post, path = "/api/documents", tag = "Documents", request_body = CreateDocumentRequest, responses((status = 200, body = Document)))]
pub async fn create_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Json(req): Json<CreateDocumentRequest>,
) -> Result<Json<Document>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let title = req.title.unwrap_or_else(|| "Untitled".into());
    let dtype = req.r#type.unwrap_or_else(|| "document".into());
    let service = ctx.document_service();
    let doc = service
        .create_for_user(user_id, &title, req.parent_id, &dtype)
        .await
        .map_err(map_service_error)?;

    Ok(Json(to_http_document(doc)))
}

#[utoipa::path(get, path = "/api/documents/{id}", tag = "Documents",
    params(("id" = Uuid, Path, description = "Document ID"), ("token" = Option<String>, Query, description = "Share token (optional)")),
    responses((status = 200, body = Document)))]
pub async fn get_document(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Document>, StatusCode> {
    let token = params.get("token").map(|s| s.as_str());
    let actor = auth::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let service = ctx.document_service();
    let doc = service
        .get_for_actor(&actor, id)
        .await
        .map_err(map_service_error)?;

    Ok(Json(to_http_document(doc)))
}

#[utoipa::path(delete, path = "/api/documents/{id}", tag = "Documents", params(("id" = Uuid, Path, description = "Document ID"),), responses((status = 204)))]
pub async fn delete_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let service = ctx.document_service();
    let ok = service
        .delete_for_user(id, user_id)
        .await
        .map_err(map_service_error)?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[utoipa::path(get, path = "/api/documents/{id}/content", tag = "Documents", params(("id" = Uuid, Path, description = "Document ID"),), responses((status = 200)))]
pub async fn get_document_content(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let actor = access::Actor::User(user_id);
    let service = ctx.document_service();
    let content = service
        .get_content(&actor, id)
        .await
        .map_err(map_service_error)?;
    Ok(Json(serde_json::json!({"content": content})))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateDocumentContentRequest {
    pub content: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DocumentPatchOperationRequest {
    Insert {
        offset: usize,
        text: String,
    },
    Delete {
        offset: usize,
        length: usize,
    },
    Replace {
        offset: usize,
        length: usize,
        text: String,
    },
}

impl From<DocumentPatchOperationRequest> for DocumentPatchOperation {
    fn from(value: DocumentPatchOperationRequest) -> Self {
        match value {
            DocumentPatchOperationRequest::Insert { offset, text } => {
                DocumentPatchOperation::Insert { offset, text }
            }
            DocumentPatchOperationRequest::Delete { offset, length } => {
                DocumentPatchOperation::Delete { offset, length }
            }
            DocumentPatchOperationRequest::Replace {
                offset,
                length,
                text,
            } => DocumentPatchOperation::Replace {
                offset,
                length,
                text,
            },
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PatchDocumentContentRequest {
    pub operations: Vec<DocumentPatchOperationRequest>,
}

#[utoipa::path(
    put,
    path = "/api/documents/{id}/content",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    request_body = UpdateDocumentContentRequest,
    responses((status = 200, body = Document))
)]
pub async fn update_document_content(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Path(id): Path<Uuid>,
    q: Option<Query<SnapshotTokenQuery>>,
    Json(body): Json<UpdateDocumentContentRequest>,
) -> Result<Json<Document>, StatusCode> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = auth::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let service = ctx.document_service();
    let updated = service
        .update_content(&actor, id, &body.content)
        .await
        .map_err(map_service_error)?;
    Ok(Json(to_http_document(updated)))
}

#[utoipa::path(
    patch,
    path = "/api/documents/{id}/content",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    request_body = PatchDocumentContentRequest,
    responses((status = 200, body = Document))
)]
pub async fn patch_document_content(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Path(id): Path<Uuid>,
    q: Option<Query<SnapshotTokenQuery>>,
    Json(body): Json<PatchDocumentContentRequest>,
) -> Result<Json<Document>, StatusCode> {
    if body.operations.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = auth::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let service = ctx.document_service();
    let operations: Vec<DocumentPatchOperation> = body
        .operations
        .into_iter()
        .map(DocumentPatchOperation::from)
        .collect();
    let updated = service
        .patch_content(&actor, id, &operations)
        .await
        .map_err(map_service_error)?;
    Ok(Json(to_http_document(updated)))
}

#[allow(dead_code)]
#[derive(ToSchema)]
pub struct DocumentDownloadBinary(#[schema(value_type = String, format = Binary)] Vec<u8>);

#[allow(dead_code)]
#[derive(ToSchema)]
pub struct DocumentArchiveBinary(#[schema(value_type = String, format = Binary)] Vec<u8>);

#[derive(Debug, Clone, Copy, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
#[schema(rename_all = "snake_case")]
pub enum DownloadFormat {
    #[default]
    Archive,
    Markdown,
    Html,
    Html5,
    Pdf,
    Docx,
    Latex,
    Beamer,
    Context,
    Man,
    Mediawiki,
    Dokuwiki,
    Textile,
    Org,
    Texinfo,
    Opml,
    Docbook,
    Opendocument,
    Odt,
    Rtf,
    Epub,
    Epub3,
    Fb2,
    Asciidoc,
    Icml,
    Slidy,
    Slideous,
    Dzslides,
    Revealjs,
    S5,
    Json,
    Plain,
    Commonmark,
    CommonmarkX,
    MarkdownStrict,
    MarkdownPhpextra,
    MarkdownGithub,
    Rst,
    Native,
    Haddock,
}

impl From<DownloadFormat> for DocumentDownloadFormat {
    fn from(value: DownloadFormat) -> Self {
        match value {
            DownloadFormat::Archive => DocumentDownloadFormat::Archive,
            DownloadFormat::Markdown => DocumentDownloadFormat::Markdown,
            DownloadFormat::Html => DocumentDownloadFormat::Html,
            DownloadFormat::Html5 => DocumentDownloadFormat::Html5,
            DownloadFormat::Pdf => DocumentDownloadFormat::Pdf,
            DownloadFormat::Docx => DocumentDownloadFormat::Docx,
            DownloadFormat::Latex => DocumentDownloadFormat::Latex,
            DownloadFormat::Beamer => DocumentDownloadFormat::Beamer,
            DownloadFormat::Context => DocumentDownloadFormat::Context,
            DownloadFormat::Man => DocumentDownloadFormat::Man,
            DownloadFormat::Mediawiki => DocumentDownloadFormat::MediaWiki,
            DownloadFormat::Dokuwiki => DocumentDownloadFormat::Dokuwiki,
            DownloadFormat::Textile => DocumentDownloadFormat::Textile,
            DownloadFormat::Org => DocumentDownloadFormat::Org,
            DownloadFormat::Texinfo => DocumentDownloadFormat::Texinfo,
            DownloadFormat::Opml => DocumentDownloadFormat::Opml,
            DownloadFormat::Docbook => DocumentDownloadFormat::Docbook,
            DownloadFormat::Opendocument => DocumentDownloadFormat::OpenDocument,
            DownloadFormat::Odt => DocumentDownloadFormat::Odt,
            DownloadFormat::Rtf => DocumentDownloadFormat::Rtf,
            DownloadFormat::Epub => DocumentDownloadFormat::Epub,
            DownloadFormat::Epub3 => DocumentDownloadFormat::Epub3,
            DownloadFormat::Fb2 => DocumentDownloadFormat::Fb2,
            DownloadFormat::Asciidoc => DocumentDownloadFormat::Asciidoc,
            DownloadFormat::Icml => DocumentDownloadFormat::Icml,
            DownloadFormat::Slidy => DocumentDownloadFormat::Slidy,
            DownloadFormat::Slideous => DocumentDownloadFormat::Slideous,
            DownloadFormat::Dzslides => DocumentDownloadFormat::Dzslides,
            DownloadFormat::Revealjs => DocumentDownloadFormat::Revealjs,
            DownloadFormat::S5 => DocumentDownloadFormat::S5,
            DownloadFormat::Json => DocumentDownloadFormat::Json,
            DownloadFormat::Plain => DocumentDownloadFormat::Plain,
            DownloadFormat::Commonmark => DocumentDownloadFormat::Commonmark,
            DownloadFormat::CommonmarkX => DocumentDownloadFormat::CommonmarkX,
            DownloadFormat::MarkdownStrict => DocumentDownloadFormat::MarkdownStrict,
            DownloadFormat::MarkdownPhpextra => DocumentDownloadFormat::MarkdownPhpextra,
            DownloadFormat::MarkdownGithub => DocumentDownloadFormat::MarkdownGithub,
            DownloadFormat::Rst => DocumentDownloadFormat::Rst,
            DownloadFormat::Native => DocumentDownloadFormat::Native,
            DownloadFormat::Haddock => DocumentDownloadFormat::Haddock,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema, Default)]
pub struct DownloadDocumentQuery {
    pub token: Option<String>,
    #[serde(default)]
    pub format: DownloadFormat,
}

#[utoipa::path(
    get,
    path = "/api/documents/{id}/download",
    tag = "Documents",
    operation_id = "download_document",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)"),
        ("format" = Option<DownloadFormat>, Query, description = "Download format (see schema for supported values)")
    ),
    responses(
        (status = 200, description = "Document download", body = DocumentDownloadBinary, content_type = "application/octet-stream"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Document not found")
    )
)]
pub async fn download_document(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Query(params): Query<DownloadDocumentQuery>,
    Path(id): Path<Uuid>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let token = params.token.as_deref();
    let format = params.format;
    let error_response = |status: StatusCode, code: &str, message: String| {
        (
            status,
            Json(json!({
                "error": code,
                "message": message,
            })),
        )
    };

    let actor = match auth::resolve_actor_from_parts(&ctx, bearer, token).await {
        Some(actor) => actor,
        None => {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Unauthorized".to_string(),
            ));
        }
    };

    let service = ctx.document_service();
    let download = match service.download_document(&actor, id, format.into()).await {
        Ok(payload) => payload,
        Err(ServiceError::Unauthorized)
        | Err(ServiceError::Forbidden)
        | Err(ServiceError::NotFound) => {
            return Err(error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "Document not found".to_string(),
            ));
        }
        Err(ServiceError::Conflict) => {
            return Err(error_response(
                StatusCode::CONFLICT,
                "conflict",
                "Document cannot be downloaded".to_string(),
            ));
        }
        Err(ServiceError::BadRequest(_)) => {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "Invalid download request".to_string(),
            ));
        }
        Err(ServiceError::Unexpected(error)) => {
            error!(
                document_id = %id,
                ?format,
                error = ?error,
                "document_download_failed"
            );
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "Failed to prepare download".to_string(),
            ));
        }
    };

    let mut headers = HeaderMap::new();
    let content_type = match HeaderValue::from_str(&download.content_type) {
        Ok(value) => value,
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_header",
                "Failed to prepare download headers".to_string(),
            ));
        }
    };
    headers.insert(axum::http::header::CONTENT_TYPE, content_type);
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    let disposition = format!("attachment; filename=\"{}\"", download.filename);
    let content_disposition = match HeaderValue::from_str(&disposition) {
        Ok(value) => value,
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_header",
                "Failed to prepare download headers".to_string(),
            ));
        }
    };
    headers.insert(axum::http::header::CONTENT_DISPOSITION, content_disposition);

    Ok((headers, download.bytes).into_response())
}

#[utoipa::path(patch, path = "/api/documents/{id}", tag = "Documents", request_body = UpdateDocumentRequest,
    params(("id" = Uuid, Path, description = "Document ID"),), responses((status = 200, body = Document)))]
pub async fn update_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateDocumentRequest>,
) -> Result<Json<Document>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let parent_opt = match req.parent_id.clone() {
        DoubleOption::NotProvided => None,
        DoubleOption::Null => Some(None),
        DoubleOption::Some(v) => Some(Some(v)),
    };
    let service = ctx.document_service();
    let doc = service
        .update_metadata(id, user_id, req.title.clone(), parent_opt)
        .await
        .map_err(map_service_error)?;
    Ok(Json(to_http_document(doc)))
}

#[utoipa::path(
    post,
    path = "/api/documents/{id}/archive",
    tag = "Documents",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses(
        (status = 200, body = Document),
        (status = 404, description = "Document not found"),
        (status = 409, description = "Document already archived")
    )
)]
pub async fn archive_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<Document>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let doc = ctx
        .document_service()
        .archive_document(id, user_id)
        .await
        .map_err(map_service_error)?;
    Ok(Json(to_http_document(doc)))
}

#[utoipa::path(
    post,
    path = "/api/documents/{id}/unarchive",
    tag = "Documents",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses(
        (status = 200, body = Document),
        (status = 404, description = "Document not found"),
        (status = 409, description = "Document is not archived")
    )
)]
pub async fn unarchive_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<Document>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let doc = ctx
        .document_service()
        .unarchive_document(id, user_id)
        .await
        .map_err(map_service_error)?;
    Ok(Json(to_http_document(doc)))
}

#[utoipa::path(
    get,
    path = "/api/documents/{id}/snapshots",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)"),
        ("limit" = Option<i64>, Query, description = "Maximum number of snapshots to return"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination")
    ),
    responses((status = 200, body = SnapshotListResponse))
)]
pub async fn list_document_snapshots(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Path(id): Path<Uuid>,
    q: Option<Query<ListSnapshotsQuery>>,
) -> Result<Json<SnapshotListResponse>, StatusCode> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = auth::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);

    let service = ctx.document_service();
    let records = service
        .list_snapshots(&actor, id, limit, offset)
        .await
        .map_err(map_service_error)?;
    let items = records.into_iter().map(snapshot_summary_from).collect();

    Ok(Json(SnapshotListResponse { items }))
}

#[utoipa::path(
    get,
    path = "/api/documents/{id}/snapshots/{snapshot_id}/diff",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("snapshot_id" = Uuid, Path, description = "Snapshot ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)"),
        ("compare" = Option<Uuid>, Query, description = "Snapshot ID to compare against (defaults to current document state)"),
        ("base" = Option<SnapshotDiffBaseParam>, Query, description = "Base comparison to use when compare is not provided (auto|current|previous)")
    ),
    responses((status = 200, body = SnapshotDiffResponse))
)]
pub async fn get_document_snapshot_diff(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Path((id, snapshot_id)): Path<(Uuid, Uuid)>,
    q: Option<Query<SnapshotDiffQuery>>,
) -> Result<Json<SnapshotDiffResponse>, StatusCode> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = auth::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let base_mode = params
        .base
        .map(SnapshotDiffBaseMode::from)
        .unwrap_or(SnapshotDiffBaseMode::Auto);

    let service = ctx.document_service();
    let result = service
        .snapshot_diff(&actor, id, snapshot_id, params.compare, base_mode)
        .await
        .map_err(map_service_error)?;

    let diff = result.diff;
    let base = snapshot_diff_side_response_from(result.base);
    let target = snapshot_diff_side_response_from(result.target);

    Ok(Json(SnapshotDiffResponse { base, target, diff }))
}

#[utoipa::path(
    post,
    path = "/api/documents/{id}/snapshots/{snapshot_id}/restore",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("snapshot_id" = Uuid, Path, description = "Snapshot ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    responses((status = 200, body = SnapshotRestoreResponse))
)]
pub async fn restore_document_snapshot(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Path((id, snapshot_id)): Path<(Uuid, Uuid)>,
    q: Option<Query<SnapshotTokenQuery>>,
) -> Result<Json<SnapshotRestoreResponse>, StatusCode> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = auth::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let service = ctx.document_service();
    let restored = service
        .restore_snapshot(&actor, id, snapshot_id)
        .await
        .map_err(map_service_error)?;

    Ok(Json(SnapshotRestoreResponse {
        snapshot: snapshot_summary_from(restored),
    }))
}

#[utoipa::path(
    get,
    path = "/api/documents/{id}/snapshots/{snapshot_id}/download",
    tag = "Documents",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("snapshot_id" = Uuid, Path, description = "Snapshot ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    responses(
        (status = 200, description = "Snapshot archive", body = DocumentArchiveBinary, content_type = "application/zip"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Snapshot not found")
    )
)]
pub async fn download_document_snapshot(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Path((id, snapshot_id)): Path<(Uuid, Uuid)>,
    q: Option<Query<SnapshotTokenQuery>>,
) -> Result<Response, StatusCode> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = auth::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let service = ctx.document_service();
    let download = service
        .download_snapshot(&actor, id, snapshot_id)
        .await
        .map_err(map_service_error)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    let disposition = format!("attachment; filename=\"{}\"", download.filename);
    let content_disposition =
        HeaderValue::from_str(&disposition).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    headers.insert(axum::http::header::CONTENT_DISPOSITION, content_disposition);

    Ok((headers, download.bytes).into_response())
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/documents", get(list_documents).post(create_document))
        .route(
            "/documents/:id",
            get(get_document)
                .delete(delete_document)
                .patch(update_document),
        )
        .route(
            "/documents/:id/content",
            get(get_document_content)
                .put(update_document_content)
                .patch(patch_document_content),
        )
        .route("/documents/:id/archive", post(archive_document))
        .route("/documents/:id/unarchive", post(unarchive_document))
        .route("/documents/:id/snapshots", get(list_document_snapshots))
        .route(
            "/documents/:id/snapshots/:snapshot_id/diff",
            get(get_document_snapshot_diff),
        )
        .route(
            "/documents/:id/snapshots/:snapshot_id/restore",
            post(restore_document_snapshot),
        )
        .route(
            "/documents/:id/snapshots/:snapshot_id/download",
            get(download_document_snapshot),
        )
        .route("/documents/:id/download", get(download_document))
        .route("/documents/:id/backlinks", get(get_backlinks))
        .route("/documents/:id/links", get(get_outgoing_links))
        .route("/documents/search", get(search_documents))
        .with_state(ctx)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResult {
    pub id: Uuid,
    pub title: String,
    pub document_type: String,
    pub path: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListSnapshotsQuery {
    pub token: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SnapshotDiffQuery {
    pub token: Option<String>,
    pub compare: Option<Uuid>,
    #[serde(default)]
    pub base: Option<SnapshotDiffBaseParam>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SnapshotTokenQuery {
    pub token: Option<String>,
}

#[utoipa::path(get, path = "/api/documents/search", tag = "Documents",
    params(("q" = Option<String>, Query, description = "Query")),
    responses((status = 200, body = [SearchResult])))]
pub async fn search_documents(
    State(ctx): State<AppContext>,
    bearer: crate::presentation::http::auth::Bearer,
    q: Option<Query<SearchQuery>>,
) -> Result<Json<Vec<SearchResult>>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let query_text = q.and_then(|Query(v)| v.q);

    let service = ctx.document_service();
    let hits = service
        .search_for_user(user_id, query_text, 20)
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

#[derive(Debug, Serialize, ToSchema)]
pub struct BacklinkInfo {
    pub document_id: String,
    pub title: String,
    pub document_type: String,
    pub file_path: Option<String>,
    pub link_type: String,
    pub link_text: Option<String>,
    pub link_count: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BacklinksResponse {
    pub backlinks: Vec<BacklinkInfo>,
    pub total_count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OutgoingLink {
    pub document_id: String,
    pub title: String,
    pub document_type: String,
    pub file_path: Option<String>,
    pub link_type: String,
    pub link_text: Option<String>,
    pub position_start: Option<i32>,
    pub position_end: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OutgoingLinksResponse {
    pub links: Vec<OutgoingLink>,
    pub total_count: usize,
}

#[utoipa::path(get, path = "/api/documents/{id}/backlinks", tag = "Documents", operation_id = "getBacklinks",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, body = BacklinksResponse)))]
pub async fn get_backlinks(
    State(ctx): State<AppContext>,
    bearer: crate::presentation::http::auth::Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<BacklinksResponse>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let actor = access::Actor::User(user_id);
    let service = ctx.document_service();
    let items = service
        .backlinks(&actor, user_id, id)
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
    bearer: crate::presentation::http::auth::Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<OutgoingLinksResponse>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let actor = access::Actor::User(user_id);
    let service = ctx.document_service();
    let items = service
        .outgoing_links(&actor, user_id, id)
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
