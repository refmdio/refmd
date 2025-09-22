use axum::{
    Json, Router,
    extract::{Multipart, Path as AxumPath, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::access;
use crate::application::use_cases::files::upload_file::UploadFile;
use crate::bootstrap::app_context::AppContext;
use crate::presentation::http::auth::{self, Bearer};

// Uses AppContext as router state

#[derive(Debug, Serialize, ToSchema)]
pub struct UploadFileResponse {
    pub id: Uuid,
    pub url: String,
    pub filename: String,
    pub content_type: Option<String>,
    pub size: i64,
}

#[derive(ToSchema)]
#[allow(dead_code)]
pub struct UploadFileMultipart {
    /// File to upload
    #[schema(value_type = String, format = Binary)]
    file: String,
    /// Target document ID
    #[schema(value_type = String, format = Uuid)]
    document_id: String,
}

/// POST /api/files (multipart/form-data)
/// Fields:
/// - file: binary file (required)
/// - document_id: uuid (required by current schema)
#[utoipa::path(
    post,
    path = "/api/files",
    tag = "Files",
    request_body(
        content = UploadFileMultipart,
        content_type = "multipart/form-data",
    ),
    responses(
        (status = 201, description = "File uploaded", body = UploadFileResponse)
    )
)]
pub async fn upload_file(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    mut multipart: Multipart,
) -> Result<Json<UploadFileResponse>, StatusCode> {
    // Validate user via bearer
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut document_id: Option<Uuid> = None;
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut orig_filename: Option<String> = None;
    let mut content_type: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        let name = field.name().map(|s| s.to_string());
        let file_name = field.file_name().map(|s| s.to_string());
        let ct = field.content_type().map(|s| s.to_string());
        match name.as_deref() {
            Some("document_id") => {
                let t = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                document_id = Uuid::parse_str(t.trim()).ok();
            }
            Some("file") => {
                // Read file field (allow any extension/MIME; size limit enforced below)
                orig_filename = file_name.clone();
                content_type = ct.clone();
                let data = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                // Enforce configured max upload size (additional safety besides DefaultBodyLimit)
                if data.len() > ctx.cfg.upload_max_bytes {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                file_bytes = Some(data.to_vec());
            }
            _ => { /* ignore additional fields */ }
        }
    }

    let doc_id = document_id.ok_or(StatusCode::BAD_REQUEST)?;
    let bytes = file_bytes.ok_or(StatusCode::BAD_REQUEST)?;

    // Use use-case to enforce ownership and persist
    let repo = ctx.files_repo();
    let storage = ctx.storage_port();
    let public_base_url = ctx.cfg.public_base_url.clone();
    let uc = UploadFile {
        repo: repo.as_ref(),
        storage: storage.as_ref(),
        public_base_url,
    };
    let out = uc
        .execute(user_id, doc_id, bytes, orig_filename, content_type.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let f = out.ok_or(StatusCode::FORBIDDEN)?;
    Ok(Json(UploadFileResponse {
        id: f.id,
        url: f.url,
        filename: f.filename,
        content_type: f.content_type,
        size: f.size,
    }))
}

/// GET /api/files/{id} -> bytes (fallback; primary is /uploads/{filename})
#[utoipa::path(
    get,
    path = "/api/files/{id}",
    tag = "Files",
    params(("id" = Uuid, Path, description = "File ID")),
    responses((status = 200, description = "OK", body = Vec<u8>, content_type = "application/octet-stream"))
)]
pub async fn get_file(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Response, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let repo = ctx.files_repo();
    let storage = ctx.storage_port();
    let meta = repo
        .get_file_meta(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (path, ct, owner_id) = meta.ok_or(StatusCode::NOT_FOUND)?;
    if owner_id != user_id {
        return Err(StatusCode::FORBIDDEN);
    }
    let data = storage
        .read_bytes(Path::new(&path))
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let mut headers = HeaderMap::new();
    if let Some(ct) = ct {
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_str(&ct)
                .unwrap_or(HeaderValue::from_static("application/octet-stream")),
        );
    }
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    Ok((headers, data).into_response())
}

#[derive(Debug, Deserialize)]
pub struct FileByNameQuery {
    pub document_id: Uuid,
}

/// GET /api/files/documents/{filename}?document_id=uuid -> bytes
#[utoipa::path(
    get,
    path = "/api/files/documents/{filename}",
    tag = "Files",
    params(("filename" = String, Path, description = "File name"), ("document_id" = Uuid, Query, description = "Document ID")),
    responses((status = 200, description = "OK", body = Vec<u8>, content_type = "application/octet-stream"))
)]
pub async fn get_file_by_name(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    AxumPath(filename): AxumPath<String>,
    Query(q): Query<FileByNameQuery>,
) -> Result<Response, StatusCode> {
    // auth: owner of the document only
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // authorize: owner must have at least view permission
    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    let actor = access::Actor::User(user_id);
    access::require_view(
        access_repo.as_ref(),
        share_access.as_ref(),
        &actor,
        q.document_id,
    )
    .await
    .map_err(|_| StatusCode::FORBIDDEN)?;

    // find file by document_id + filename
    let repo = ctx.files_repo();
    let (path, ct) = repo
        .get_file_path_by_doc_and_name(q.document_id, &filename)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let storage = ctx.storage_port();
    let data = storage
        .read_bytes(Path::new(&path))
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let mut headers = HeaderMap::new();
    if let Some(ct) = ct {
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_str(&ct)
                .unwrap_or(HeaderValue::from_static("application/octet-stream")),
        );
    }
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    Ok((headers, data).into_response())
}

/// Serve static files from uploads directory with authentication support
/// Supports both JWT auth and share tokens
pub async fn serve_upload(
    State(ctx): State<AppContext>,
    AxumPath(path): AxumPath<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    // Try to extract token from query params, Authorization header, or HttpOnly cookie `access_token`
    let token = params
        .get("token")
        .cloned()
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer ").map(|s| s.to_string()))
        })
        .or_else(|| {
            headers
                .get(axum::http::header::COOKIE)
                .and_then(|h| h.to_str().ok())
                .and_then(|cookie_hdr| {
                    for part in cookie_hdr.split(';') {
                        let kv = part.trim();
                        if let Some((k, v)) = kv.split_once('=') {
                            if k.trim() == "access_token" {
                                return Some(v.trim().to_string());
                            }
                        }
                    }
                    None
                })
        });

    // Path must start with document UUID. If not, reject.
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return Err(StatusCode::FORBIDDEN);
    }
    let doc_id = Uuid::parse_str(parts[0]).map_err(|_| StatusCode::FORBIDDEN)?;

    // Build actor and require at least view capability (or public)
    let actor = token
        .as_deref()
        .and_then(|t| auth::resolve_actor_from_token_str(&ctx.cfg, t))
        .unwrap_or(access::Actor::Public);
    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    let _cap = access::require_view(access_repo.as_ref(), share_access.as_ref(), &actor, doc_id)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Resolve the file path via storage port (includes security checks)
    let storage_port = ctx.storage_port();
    let attachment_path = parts[1..].join("/");
    let file_path = storage_port
        .resolve_upload_path(doc_id, &attachment_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let data = storage_port
        .read_bytes(&file_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    // Determine content type from extension using mime_guess (fallback to octet-stream)
    let guessed = mime_guess::from_path(&file_path).first_or_octet_stream();
    let content_type = guessed.essence_str().to_string();

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    Ok((headers, data).into_response())
}

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/files", post(upload_file))
        .route("/files/:id", get(get_file))
        .route("/files/documents/:filename", get(get_file_by_name))
        .with_state(ctx)
}
