use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::DocumentsContext;
use crate::http::error::ApiError;
use crate::security::token::{self, Bearer};
use application::core::services::access;
use application::core::services::errors::ServiceError;
use application::documents::services::DocumentPatchOperation;

#[allow(unused_imports)]
use crate::http::documents::types::{
    Document, DocumentArchiveBinary, DocumentDownloadBinary, DownloadDocumentQuery, DownloadFormat,
    PatchDocumentContentRequest, SnapshotTokenQuery, UpdateDocumentContentRequest,
    map_service_error, to_http_document,
};

#[utoipa::path(get, path = "/api/documents/{id}/content", tag = "Documents", params(("id" = Uuid, Path, description = "Document ID"),), responses((status = 200)))]
pub async fn get_document_content(
    State(ctx): State<DocumentsContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let user_id = token::require_user_id(&ctx, bearer)
        .await
        .map_err(token::map_actor_error)?;
    let actor = access::Actor::User(user_id);
    let service = ctx.document_service();
    let content = service
        .get_content(&actor, id)
        .await
        .map_err(map_service_error)?;
    Ok(Json(json!({"content": content})))
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
    State(ctx): State<DocumentsContext>,
    bearer: Option<Bearer>,
    Path(id): Path<Uuid>,
    q: Option<Query<SnapshotTokenQuery>>,
    Json(body): Json<UpdateDocumentContentRequest>,
) -> Result<Json<Document>, ApiError> {
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .map_err(token::map_actor_error)?
        .ok_or(ApiError::unauthorized("unauthorized"))?;
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
    State(ctx): State<DocumentsContext>,
    bearer: Option<Bearer>,
    Path(id): Path<Uuid>,
    q: Option<Query<SnapshotTokenQuery>>,
    Json(body): Json<PatchDocumentContentRequest>,
) -> Result<Json<Document>, ApiError> {
    if body.operations.is_empty() {
        return Err(ApiError::bad_request("missing_operations"));
    }
    let params = q.map(|Query(v)| v).unwrap_or_default();
    let token = params.token.as_deref();
    let actor = token::resolve_actor_from_parts(&ctx, bearer, token)
        .await
        .map_err(token::map_actor_error)?
        .ok_or(ApiError::unauthorized("unauthorized"))?;
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
    State(ctx): State<DocumentsContext>,
    bearer: Option<Bearer>,
    Query(params): Query<DownloadDocumentQuery>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let token = params.token.as_deref();
    let format = params.format;

    let actor = match token::resolve_actor_from_parts(&ctx, bearer, token).await {
        Ok(Some(actor)) => actor,
        Ok(None) => return Err(ApiError::unauthorized("unauthorized")),
        Err(err) => return Err(token::map_actor_error(err)),
    };

    let service = ctx.document_service();
    let download = match service.download_document(&actor, id, format.into()).await {
        Ok(payload) => payload,
        Err(ServiceError::Unauthorized)
        | Err(ServiceError::TokenExpired)
        | Err(ServiceError::Forbidden)
        | Err(ServiceError::NotFound) => {
            return Err(ApiError::not_found("not_found"));
        }
        Err(ServiceError::Conflict) => {
            return Err(ApiError::conflict("conflict"));
        }
        Err(ServiceError::BadRequest(_)) => {
            return Err(ApiError::bad_request("bad_request"));
        }
        Err(ServiceError::Unexpected(error)) => {
            tracing::error!(
                document_id = %id,
                ?format,
                error = ?error,
                "document_download_failed"
            );
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ));
        }
    };

    let mut headers = HeaderMap::new();
    let content_type = match HeaderValue::from_str(&download.content_type) {
        Ok(value) => value,
        Err(_) => {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
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
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ));
        }
    };
    headers.insert(axum::http::header::CONTENT_DISPOSITION, content_disposition);

    Ok((headers, download.bytes).into_response())
}
