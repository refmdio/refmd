use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use crate::application::services::errors::ServiceError;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::Bearer;
use crate::presentation::http::documents::{Document, to_http_document};
use crate::presentation::http::workspaces::scope as workspace_scope;

use super::types::{PublicDocumentSummary, PublishResponse};

fn map_public_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized | ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            tracing::error!(error = ?inner, "public_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/public/documents/{id}",
    tag = "Public Documents",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, description = "Published", body = PublishResponse))
)]
pub async fn publish_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<PublishResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let service = ctx.public_service();
    let out = service
        .publish_document(workspace_id, &permissions, id)
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let ok = ctx
        .public_service()
        .unpublish_document(workspace_id, &permissions, id)
        .await
        .map_err(map_public_error)?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::FORBIDDEN)
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<PublishResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let out = ctx
        .public_service()
        .get_publish_status(workspace_id, &permissions, id)
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
    State(ctx): State<AppContext>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<PublicDocumentSummary>>, StatusCode> {
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
    State(ctx): State<AppContext>,
    Path((slug, id)): Path<(String, Uuid)>,
) -> Result<Json<Document>, StatusCode> {
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
    State(ctx): State<AppContext>,
    Path((slug, id)): Path<(String, Uuid)>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let content = ctx
        .public_service()
        .get_public_content_by_workspace_and_id(&slug, id)
        .await
        .map_err(map_public_error)?;
    Ok(Json(serde_json::json!({"content": content, "id": id})))
}
