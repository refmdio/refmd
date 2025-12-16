use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;

use crate::domain::workspaces::permissions::PERM_DOC_VIEW;
use crate::presentation::context::AppContext;
use crate::presentation::http::auth::Bearer;
use crate::presentation::http::workspaces::scope as workspace_scope;

use super::types::{
    CreateDocumentRequest, Document, DocumentListResponse, DocumentStateFilter,
    DuplicateDocumentRequest, DoubleOption, ListDocumentsQuery, UpdateDocumentRequest,
    map_service_error, to_http_document,
};

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
    headers: HeaderMap,
    q: Option<Query<ListDocumentsQuery>>,
) -> Result<Json<DocumentListResponse>, StatusCode> {
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
    workspace_scope::ensure_workspace_permission(&ctx, workspace_id, user_id, PERM_DOC_VIEW)
        .await?;
    let (qstr, tag, state_param) = q
        .map(|Query(v)| (v.query, v.tag, v.state))
        .unwrap_or((None, None, None));
    let state = state_param
        .map(DocumentStateFilter::into)
        .unwrap_or_default();

    let service = ctx.document_service();
    let docs = service
        .list_for_user(workspace_id, qstr, tag, state)
        .await
        .map_err(map_service_error)?;

    let items: Vec<Document> = docs.into_iter().map(to_http_document).collect();
    Ok(Json(DocumentListResponse { items }))
}

#[utoipa::path(post, path = "/api/documents", tag = "Documents", request_body = CreateDocumentRequest, responses((status = 200, body = Document)))]
pub async fn create_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<CreateDocumentRequest>,
) -> Result<Json<Document>, StatusCode> {
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
    let title = req.title.unwrap_or_else(|| "Untitled".into());
    let dtype = req.r#type.unwrap_or_else(|| "document".into());
    let service = ctx.document_service();
    let doc = service
        .create_for_user(
            workspace_id,
            user_id,
            &permissions,
            &title,
            req.parent_id,
            &dtype,
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
    State(ctx): State<AppContext>,
    bearer: Option<Bearer>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Document>, StatusCode> {
    let token = params.get("token").map(|s| s.as_str());
    let actor = crate::presentation::http::auth::resolve_actor_from_parts(&ctx, bearer, token)
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
    let service = ctx.document_service();
    let ok = service
        .delete_for_user(workspace_id, id, Some(user_id), &permissions)
        .await
        .map_err(map_service_error)?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[utoipa::path(patch, path = "/api/documents/{id}", tag = "Documents", request_body = UpdateDocumentRequest,
    params(("id" = Uuid, Path, description = "Document ID"),), responses((status = 200, body = Document)))]
pub async fn update_document(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateDocumentRequest>,
) -> Result<Json<Document>, StatusCode> {
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
    let parent_opt = match req.parent_id.clone() {
        DoubleOption::NotProvided => None,
        DoubleOption::Null => Some(None),
        DoubleOption::Some(v) => Some(Some(v)),
    };
    let service = ctx.document_service();
    let doc = service
        .update_metadata(
            workspace_id,
            id,
            user_id,
            &permissions,
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<DuplicateDocumentRequest>,
) -> Result<Json<Document>, StatusCode> {
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
    let parent_opt = match req.parent_id.clone() {
        DoubleOption::NotProvided => None,
        DoubleOption::Null => Some(None),
        DoubleOption::Some(v) => Some(Some(v)),
    };
    let doc = ctx
        .document_service()
        .duplicate_document(
            workspace_id,
            id,
            user_id,
            &permissions,
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
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Document>, StatusCode> {
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
    let doc = ctx
        .document_service()
        .archive_document(workspace_id, id, user_id, &permissions)
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
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Document>, StatusCode> {
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
    let doc = ctx
        .document_service()
        .unarchive_document(workspace_id, id, user_id, &permissions)
        .await
        .map_err(map_service_error)?;
    Ok(Json(to_http_document(doc)))
}
