use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use uuid::Uuid;

use application::access;
use application::services::documents::DocumentPatchOperation;
use application::services::errors::ServiceError;
use crate::context::AppContext;
use crate::http::auth::{self, Bearer};

#[allow(unused_imports)]
use super::types::{
    Document, DocumentArchiveBinary, DocumentDownloadBinary, DownloadDocumentQuery, DownloadFormat,
    PatchDocumentContentRequest, SnapshotTokenQuery, UpdateDocumentContentRequest,
    map_service_error, to_http_document,
};

#[utoipa::path(get, path = "/api/documents/{id}/content", tag = "Documents", params(("id" = Uuid, Path, description = "Document ID"),), responses((status = 200)))]
pub async fn get_document_content(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, StatusCode> {
    let sub = crate::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
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
        | Err(ServiceError::TokenExpired)
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
            tracing::error!(
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
