use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::http::extractors::WorkspaceAuth;
use crate::security::token::{self, Bearer};
use application::domain::access::permissions::PERM_DOC_VIEW;
use application::domain::documents::doc_type::DocumentType;

use crate::http::documents::types::{
    CreateDocumentRequest, Document, DocumentListResponse, DocumentStateFilter, DoubleOption,
    DuplicateDocumentRequest, ListDocumentsQuery, UpdateDocumentRequest, map_service_error,
    to_http_document,
};

#[utoipa::path(get, path = "/api/documents", tag = "Documents",
    params(
        ("query" = Option<String>, Query, description = "Search query"),
        ("tag" = Option<String>, Query, description = "Filter by tag"),
        ("state" = Option<String>, Query, description = "Filter by document state (active|archived|all)")
    ),
    responses((status = 200, body = DocumentListResponse)))]
pub async fn list_documents(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    q: Option<Query<ListDocumentsQuery>>,
) -> Result<Json<DocumentListResponse>, ApiError> {
    auth.ensure_permission(PERM_DOC_VIEW)?;
    let (qstr, tag, state_param) = q
        .map(|Query(v)| (v.query, v.tag, v.state))
        .unwrap_or((None, None, None));
    let state = state_param
        .map(DocumentStateFilter::into)
        .unwrap_or_default();

    let service = ctx.document_service();
    let docs = service
        .list_for_user(auth.workspace_id, qstr, tag, state)
        .await
        .map_err(map_service_error)?;

    let items: Vec<Document> = docs.into_iter().map(to_http_document).collect();
    Ok(Json(DocumentListResponse { items }))
}

#[utoipa::path(post, path = "/api/documents", tag = "Documents", request_body = CreateDocumentRequest, responses((status = 200, body = Document)))]
pub async fn create_document(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Json(req): Json<CreateDocumentRequest>,
) -> Result<Json<Document>, ApiError> {
    let title = req.title.unwrap_or_else(|| "Untitled".into());
    let dtype = req
        .r#type
        .unwrap_or_else(|| DocumentType::Document.as_str().to_string());
    let doc_type = DocumentType::try_from(dtype.as_str())
        .map_err(|_| ApiError::bad_request("invalid_document_type"))?;
    let service = ctx.document_service();
    let doc = service
        .create_for_user(
            auth.workspace_id,
            auth.user_id,
            &auth.permissions,
            &title,
            req.parent_id,
            doc_type,
            None,
        )
        .await
        .map_err(map_service_error)?;

    Ok(Json(to_http_document(doc)))
}

#[utoipa::path(get, path = "/api/documents/{id}", tag = "Documents",
    params(("id" = Uuid, Path, description = "Document ID"), ("token" = Option<String>, Query, description = "Share token (optional)")),
    responses((status = 200, body = Document)))]
pub async fn get_document(
    State(ctx): State<DocumentsContext>,
    bearer: Option<Bearer>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Document>, ApiError> {
    let token = params.get("token").map(|s| s.as_str());
    let actor = token::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .map_err(token::map_actor_error)?
        .ok_or(ApiError::unauthorized("unauthorized"))?;
    let service = ctx.document_service();
    let doc = service
        .get_for_actor(&actor, id)
        .await
        .map_err(map_service_error)?;

    Ok(Json(to_http_document(doc)))
}

#[utoipa::path(delete, path = "/api/documents/{id}", tag = "Documents", params(("id" = Uuid, Path, description = "Document ID"),), responses((status = 204)))]
pub async fn delete_document(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let service = ctx.document_service();
    let ok = service
        .delete_for_user(auth.workspace_id, id, Some(auth.user_id), &auth.permissions)
        .await
        .map_err(map_service_error)?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("not_found"))
    }
}

#[utoipa::path(patch, path = "/api/documents/{id}", tag = "Documents", request_body = UpdateDocumentRequest,
    params(("id" = Uuid, Path, description = "Document ID"),), responses((status = 200, body = Document)))]
pub async fn update_document(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateDocumentRequest>,
) -> Result<Json<Document>, ApiError> {
    let parent_opt = match req.parent_id.clone() {
        DoubleOption::NotProvided => None,
        DoubleOption::Null => Some(None),
        DoubleOption::Some(v) => Some(Some(v)),
    };
    let service = ctx.document_service();
    let doc = service
        .update_metadata(
            auth.workspace_id,
            id,
            auth.user_id,
            &auth.permissions,
            req.title.clone(),
            parent_opt,
        )
        .await
        .map_err(map_service_error)?;
    Ok(Json(to_http_document(doc)))
}

#[utoipa::path(
    post,
    path = "/api/documents/{id}/duplicate",
    tag = "Documents",
    request_body = DuplicateDocumentRequest,
    params(("id" = Uuid, Path, description = "Document ID"),),
    responses((status = 200, body = Document))
)]
pub async fn duplicate_document(
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<DuplicateDocumentRequest>,
) -> Result<Json<Document>, ApiError> {
    let parent_opt = match req.parent_id.clone() {
        DoubleOption::NotProvided => None,
        DoubleOption::Null => Some(None),
        DoubleOption::Some(v) => Some(Some(v)),
    };
    let doc = ctx
        .document_service()
        .duplicate_document(
            auth.workspace_id,
            id,
            auth.user_id,
            &auth.permissions,
            req.title.clone(),
            parent_opt,
        )
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
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<Document>, ApiError> {
    let doc = ctx
        .document_service()
        .archive_document(auth.workspace_id, id, auth.user_id, &auth.permissions)
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
    State(ctx): State<DocumentsContext>,
    auth: WorkspaceAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<Document>, ApiError> {
    let doc = ctx
        .document_service()
        .unarchive_document(auth.workspace_id, id, auth.user_id, &auth.permissions)
        .await
        .map_err(map_service_error)?;
    Ok(Json(to_http_document(doc)))
}
