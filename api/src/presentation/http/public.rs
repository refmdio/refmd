use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::dto::public::PublicDocumentSummaryDto;
use crate::application::services::errors::ServiceError;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::Bearer;
use crate::presentation::http::documents::Document;

// Uses AppContext as router state

#[derive(Debug, Serialize, ToSchema)]
pub struct PublishResponse {
    pub slug: String,
    pub public_url: String,
}

fn map_public_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized => StatusCode::UNAUTHORIZED,
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
    Path(id): Path<Uuid>,
) -> Result<Json<PublishResponse>, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let service = ctx.public_service();
    let out = service
        .publish_document(user_id, id)
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
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let ok = ctx
        .public_service()
        .unpublish_document(user_id, id)
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
    Path(id): Path<Uuid>,
) -> Result<Json<PublishResponse>, StatusCode> {
    // Validate ownership
    let sub = crate::presentation::http::auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let out = ctx
        .public_service()
        .get_publish_status(user_id, id)
        .await
        .map_err(map_public_error)?;
    Ok(Json(PublishResponse {
        slug: out.slug,
        public_url: out.public_url,
    }))
}

// Slug-based endpoints are intentionally omitted to simplify routing and match legacy pattern strictly.

#[derive(Debug, Serialize, ToSchema)]
pub struct PublicDocumentSummary {
    pub id: Uuid,
    pub title: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub published_at: chrono::DateTime<chrono::Utc>,
}

#[utoipa::path(
    get,
    path = "/api/public/users/{name}",
    tag = "Public Documents",
    params(("name" = String, Path, description = "Owner name")),
    responses((status = 200, description = "Public documents for user", body = [PublicDocumentSummary]))
)]
pub async fn list_user_public_documents(
    State(ctx): State<AppContext>,
    Path(name): Path<String>,
) -> Result<Json<Vec<PublicDocumentSummary>>, StatusCode> {
    let items = ctx
        .public_service()
        .list_user_public_documents(&name)
        .await
        .map_err(map_public_error)?;
    Ok(Json(
        items
            .into_iter()
            .map(|d: PublicDocumentSummaryDto| PublicDocumentSummary {
                id: d.id,
                title: d.title,
                updated_at: d.updated_at,
                published_at: d.published_at,
            })
            .collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/public/users/{name}/{id}",
    tag = "Public Documents",
    params(("name" = String, Path, description = "Owner name"), ("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, description = "Document metadata", body = Document))
)]
pub async fn get_public_by_owner_and_id(
    State(ctx): State<AppContext>,
    Path((name, id)): Path<(String, Uuid)>,
) -> Result<Json<Document>, StatusCode> {
    let d = ctx
        .public_service()
        .get_public_by_owner_and_id(&name, id)
        .await
        .map_err(map_public_error)?;
    Ok(Json(Document {
        id: d.id,
        title: d.title,
        parent_id: d.parent_id,
        r#type: d.doc_type,
        created_at: d.created_at,
        updated_at: d.updated_at,
        path: d.path,
        archived_at: d.archived_at,
        archived_by: d.archived_by,
        archived_parent_id: d.archived_parent_id,
    }))
}

#[utoipa::path(
    get,
    path = "/api/public/users/{name}/{id}/content",
    tag = "Public Documents",
    params(("name" = String, Path, description = "Owner name"), ("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, description = "Document content"))
)]
pub async fn get_public_content_by_owner_and_id(
    State(ctx): State<AppContext>,
    Path((name, id)): Path<(String, Uuid)>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let content = ctx
        .public_service()
        .get_public_content_by_owner_and_id(&name, id)
        .await
        .map_err(map_public_error)?;
    Ok(Json(serde_json::json!({"content": content, "id": id})))
}
pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route(
            "/documents/:id",
            post(publish_document)
                .delete(unpublish_document)
                .get(get_publish_status),
        )
        .route("/users/:name", get(list_user_public_documents))
        .route("/users/:name/:id", get(get_public_by_owner_and_id))
        .route(
            "/users/:name/:id/content",
            get(get_public_content_by_owner_and_id),
        )
        .with_state(ctx)
}
