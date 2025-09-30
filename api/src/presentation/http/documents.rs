use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::access;
use crate::application::use_cases::documents::create_document::CreateDocument;
use crate::application::use_cases::documents::delete_document::DeleteDocument;
use crate::application::use_cases::documents::download_document::DownloadDocument as DownloadDocumentUseCase;
use crate::application::use_cases::documents::get_backlinks::GetBacklinks;
use crate::application::use_cases::documents::get_document::GetDocument;
use crate::application::use_cases::documents::get_outgoing_links::GetOutgoingLinks;
use crate::application::use_cases::documents::list_documents::ListDocuments;
use crate::application::use_cases::documents::search_documents::SearchDocuments;
use crate::application::use_cases::documents::update_document::UpdateDocument;
use crate::bootstrap::app_context::AppContext;
use crate::domain::documents::document as domain;
use crate::presentation::http::auth::{self, Bearer};

#[derive(Debug, Serialize, ToSchema)]
pub struct Document {
    pub id: Uuid,
    pub title: String,
    pub parent_id: Option<Uuid>,
    pub r#type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub path: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentListResponse {
    pub items: Vec<Document>,
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
}

#[utoipa::path(get, path = "/api/documents", tag = "Documents",
    params(
        ("query" = Option<String>, Query, description = "Search query"),
        ("tag" = Option<String>, Query, description = "Filter by tag")
    ),
    responses((status = 200, body = DocumentListResponse)))]
pub async fn list_documents(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    q: Option<Query<ListDocumentsQuery>>,
) -> Result<Json<DocumentListResponse>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let (qstr, tag) = q.map(|Query(v)| (v.query, v.tag)).unwrap_or((None, None));

    let repo = ctx.document_repo();
    let uc = ListDocuments {
        repo: repo.as_ref(),
    };
    let docs: Vec<domain::Document> = uc
        .execute(user_id, qstr, tag)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let items: Vec<Document> = docs
        .into_iter()
        .map(|d| Document {
            id: d.id,
            title: d.title,
            parent_id: d.parent_id,
            r#type: d.doc_type,
            created_at: d.created_at,
            updated_at: d.updated_at,
            path: d.path,
        })
        .collect();
    Ok(Json(DocumentListResponse { items }))
}

#[utoipa::path(post, path = "/api/documents", tag = "Documents", request_body = CreateDocumentRequest, responses((status = 200, body = Document)))]
pub async fn create_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Json(req): Json<CreateDocumentRequest>,
) -> Result<Json<Document>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let title = req.title.unwrap_or_else(|| "Untitled".into());
    let dtype = req.r#type.unwrap_or_else(|| "document".into());

    let repo = ctx.document_repo();
    let uc = CreateDocument {
        repo: repo.as_ref(),
    };
    let doc = uc
        .execute(user_id, &title, req.parent_id, &dtype)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(Document {
        id: doc.id,
        title: doc.title,
        parent_id: doc.parent_id,
        r#type: doc.doc_type,
        created_at: doc.created_at,
        updated_at: doc.updated_at,
        path: doc.path,
    }))
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
    let actor =
        auth::resolve_actor_from_parts(&ctx.cfg, bearer, token).ok_or(StatusCode::UNAUTHORIZED)?;

    let repo = ctx.document_repo();
    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    let uc = GetDocument {
        repo: repo.as_ref(),
        shares: share_access.as_ref(),
        access: access_repo.as_ref(),
    };
    let doc = uc
        .execute(&actor, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(Document {
        id: doc.id,
        title: doc.title,
        parent_id: doc.parent_id,
        r#type: doc.doc_type,
        created_at: doc.created_at,
        updated_at: doc.updated_at,
        path: doc.path,
    }))
}

#[utoipa::path(delete, path = "/api/documents/{id}", tag = "Documents", params(("id" = Uuid, Path, description = "Document ID"),), responses((status = 204)))]
pub async fn delete_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let repo = ctx.document_repo();
    let storage = ctx.storage_port();
    let uc = DeleteDocument {
        repo: repo.as_ref(),
        storage: storage.as_ref(),
    };
    let ok = uc
        .execute(id, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    // authorization via access policy
    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    let actor = access::Actor::User(user_id);
    access::require_view(access_repo.as_ref(), share_access.as_ref(), &actor, id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    // Load content via realtime engine abstraction
    let realtime = ctx.realtime_engine();
    let content = realtime
        .get_content(&id.to_string())
        .await
        .map_err(|e| {
            tracing::error!(document_id = %id, error = ?e, "realtime_get_content_failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .unwrap_or_default();
    Ok(Json(serde_json::json!({"content": content})))
}

#[allow(dead_code)]
#[derive(ToSchema)]
pub struct DocumentArchiveBinary(#[schema(value_type = String, format = Binary)] Vec<u8>);

#[utoipa::path(
    get,
    path = "/api/documents/{id}/download",
    tag = "Documents",
    operation_id = "download_document",
    params(
        ("id" = Uuid, Path, description = "Document ID"),
        ("token" = Option<String>, Query, description = "Share token (optional)")
    ),
    responses(
        (status = 200, description = "Document archive", body = DocumentArchiveBinary, content_type = "application/zip"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Document not found")
    )
)]
pub async fn download_document(
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Path(id): Path<Uuid>,
) -> Result<Response, StatusCode> {
    let token = params.get("token").map(|s| s.as_str());
    let actor =
        auth::resolve_actor_from_parts(&ctx.cfg, bearer, token).ok_or(StatusCode::UNAUTHORIZED)?;

    let documents = ctx.document_repo();
    let files = ctx.files_repo();
    let storage = ctx.storage_port();
    let realtime = ctx.realtime_engine();
    let access = ctx.access_repo();
    let shares = ctx.share_access_port();

    let uc = DownloadDocumentUseCase {
        documents: documents.as_ref(),
        files: files.as_ref(),
        storage: storage.as_ref(),
        realtime: realtime.as_ref(),
        access: access.as_ref(),
        shares: shares.as_ref(),
    };

    let download = uc
        .execute(&actor, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    let disposition = format!("attachment; filename=\"{}\"", download.filename);
    let content_disposition =
        HeaderValue::from_str(&disposition).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let repo = ctx.document_repo();
    let storage = ctx.storage_port();
    let realtime = ctx.realtime_engine();
    let uc = UpdateDocument {
        repo: repo.as_ref(),
        storage: storage.as_ref(),
        realtime: realtime.as_ref(),
    };
    let parent_opt = match req.parent_id.clone() {
        DoubleOption::NotProvided => None,
        DoubleOption::Null => Some(None),
        DoubleOption::Some(v) => Some(Some(v)),
    };
    let doc = uc
        .execute(id, user_id, req.title.clone(), parent_opt)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(Document {
        id: doc.id,
        title: doc.title,
        parent_id: doc.parent_id,
        r#type: doc.doc_type,
        created_at: doc.created_at,
        updated_at: doc.updated_at,
        path: doc.path,
    }))
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
        .route("/documents/:id/content", get(get_document_content))
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

#[utoipa::path(get, path = "/api/documents/search", tag = "Documents",
    params(("q" = Option<String>, Query, description = "Query")),
    responses((status = 200, body = [SearchResult])))]
pub async fn search_documents(
    State(ctx): State<AppContext>,
    bearer: crate::presentation::http::auth::Bearer,
    q: Option<Query<SearchQuery>>,
) -> Result<Json<Vec<SearchResult>>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let query_text = q.and_then(|Query(v)| v.q);

    let repo = ctx.document_repo();
    let uc = SearchDocuments {
        repo: repo.as_ref(),
    };
    let hits = uc
        .execute(user_id, query_text, 20)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    let actor = access::Actor::User(user_id);
    access::require_view(access_repo.as_ref(), share_access.as_ref(), &actor, id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let repo = ctx.document_repo();
    let uc = GetBacklinks {
        repo: repo.as_ref(),
    };
    let items = uc
        .execute(user_id, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx.cfg, bearer)?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let share_access = ctx.share_access_port();
    let access_repo = ctx.access_repo();
    let actor = access::Actor::User(user_id);
    access::require_view(access_repo.as_ref(), share_access.as_ref(), &actor, id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let repo = ctx.document_repo();
    let uc = GetOutgoingLinks {
        repo: repo.as_ref(),
    };
    let items = uc
        .execute(user_id, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
