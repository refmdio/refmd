use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::access;
use crate::application::dto::shares::{
    ActiveShareItemDto, ApplicableShareDto, ShareBrowseResponseDto, ShareBrowseTreeItemDto,
    ShareDocumentDto, ShareItemDto,
};
use crate::application::services::errors::ServiceError;
use crate::presentation::context::{AppContext, PresentationConfig};
use crate::presentation::http::auth;
use crate::presentation::http::auth::Bearer;
use crate::presentation::http::workspace_scope;

fn frontend_base(cfg: &PresentationConfig) -> String {
    cfg.frontend_url
        .clone()
        .unwrap_or_else(|| "http://localhost:3000".into())
}

fn build_share_url(base: &str, document_type: &str, document_id: Uuid, token: &str) -> String {
    let base = base.trim_end_matches('/');
    if document_type == "folder" {
        format!("{}/share/{}", base, token)
    } else {
        format!("{}/document/{}?token={}", base, document_id, token)
    }
}

fn share_scope(document_type: &str) -> String {
    if document_type == "folder" {
        "folder".to_string()
    } else {
        "document".to_string()
    }
}

fn map_share_error(err: ServiceError) -> StatusCode {
    match err {
        ServiceError::Unauthorized | ServiceError::TokenExpired => StatusCode::UNAUTHORIZED,
        ServiceError::Forbidden => StatusCode::FORBIDDEN,
        ServiceError::Conflict => StatusCode::CONFLICT,
        ServiceError::NotFound => StatusCode::NOT_FOUND,
        ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ServiceError::Unexpected(inner) => {
            tracing::error!(error = ?inner, "share_service_error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

// Uses AppContext as router state

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateShareRequest {
    pub document_id: Uuid,
    pub permission: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateShareResponse {
    pub token: String,
    pub url: String,
}

#[utoipa::path(
    post,
    path = "/api/shares",
    tag = "Sharing",
    request_body = CreateShareRequest,
    responses((status = 200, description = "Share link created", body = CreateShareResponse))
)]
pub async fn create_share(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Json(req): Json<CreateShareRequest>,
) -> Result<Json<CreateShareResponse>, StatusCode> {
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
    let actor = access::Actor::User(user_id);
    ctx.authorization()
        .require_edit(&actor, req.document_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let permission = req.permission.as_deref().unwrap_or("view");
    let service = ctx.share_service();
    let res = service
        .create_share(
            workspace_id,
            user_id,
            &permissions,
            req.document_id,
            permission,
            req.expires_at,
        )
        .await
        .map_err(map_share_error)?;
    let base = frontend_base(&ctx.cfg);
    let url = build_share_url(&base, &res.document_type, res.document_id, &res.token);
    Ok(Json(CreateShareResponse {
        token: res.token,
        url,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ShareItem {
    pub id: Uuid,
    pub token: String,
    pub permission: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub url: String,
    /// document | folder
    pub scope: String,
    /// If present, this document share was materialized from a folder share
    pub parent_share_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/shares/documents/{id}",
    tag = "Sharing",
    params(("id" = Uuid, Path, description = "Document ID")),
    responses((status = 200, description = "OK", body = [ShareItem]))
)]
pub async fn list_document_shares(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<Vec<ShareItem>>, StatusCode> {
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
    // authorization: require edit on the document
    let actor = access::Actor::User(user_id);
    ctx.authorization()
        .require_edit(&actor, id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let service = ctx.share_service();
    let rows: Vec<ShareItemDto> = service
        .list_document_shares(workspace_id, &permissions, id)
        .await
        .map_err(map_share_error)?;
    let base = frontend_base(&ctx.cfg);
    let items: Vec<ShareItem> = rows
        .into_iter()
        .map(|r| {
            let ShareItemDto {
                id,
                token,
                permission,
                expires_at,
                document_id,
                document_type,
                parent_share_id,
                ..
            } = r;
            let url = build_share_url(&base, &document_type, document_id, &token);
            ShareItem {
                id,
                token,
                permission,
                expires_at,
                url,
                scope: share_scope(&document_type),
                parent_share_id,
            }
        })
        .collect();
    Ok(Json(items))
}

#[utoipa::path(
    delete,
    path = "/api/shares/{token}",
    tag = "Sharing",
    params(("token" = String, Path, description = "Share token")),
    responses((status = 204, description = "Share link deleted"))
)]
pub async fn delete_share(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    axum::extract::Path(token): axum::extract::Path<String>,
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
    let service = ctx.share_service();
    let meta = service
        .share_document_meta(&token)
        .await
        .map_err(map_share_error)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if meta.workspace_id != workspace_id {
        return Err(StatusCode::FORBIDDEN);
    }
    let actor = access::Actor::User(user_id);
    ctx.authorization()
        .require_edit(&actor, meta.document_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let ok = service
        .delete_share(workspace_id, &permissions, &token)
        .await
        .map_err(map_share_error)?;
    if ok {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Debug, Deserialize)]
pub struct ApplicableQuery {
    pub doc_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicableShareItem {
    pub token: String,
    pub permission: String,
    /// 'document' or 'folder'
    pub scope: String,
    pub excluded: bool,
}

impl From<ApplicableShareDto> for ApplicableShareItem {
    fn from(d: ApplicableShareDto) -> Self {
        ApplicableShareItem {
            token: d.token,
            permission: d.permission,
            scope: d.scope,
            excluded: d.excluded,
        }
    }
}

#[utoipa::path(get, path = "/api/shares/applicable", tag = "Sharing",
    params(("doc_id" = Uuid, Query, description = "Document ID")),
    responses((status = 200, description = "Shares that include the document", body = [ApplicableShareItem])))]
pub async fn list_applicable_shares(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    Query(q): Query<ApplicableQuery>,
) -> Result<Json<Vec<ApplicableShareItem>>, StatusCode> {
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
    // authorize: require view on the document
    let actor = access::Actor::User(user_id);
    ctx.authorization()
        .require_view(&actor, q.doc_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;

    let service = ctx.share_service();
    let rows = service
        .list_applicable(workspace_id, &permissions, q.doc_id)
        .await
        .map_err(map_share_error)?;
    let items: Vec<ApplicableShareItem> = rows.into_iter().map(Into::into).collect();
    Ok(Json(items))
}

// Share token validation for document access
#[derive(Debug, Deserialize)]
pub struct ShareTokenQuery {
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ShareDocumentResponse {
    pub id: Uuid,
    pub title: String,
    pub permission: String,
    pub content: Option<String>,
}

impl From<ShareDocumentDto> for ShareDocumentResponse {
    fn from(d: ShareDocumentDto) -> Self {
        ShareDocumentResponse {
            id: d.id,
            title: d.title,
            permission: d.permission,
            content: d.content,
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/shares/validate",
    tag = "Sharing",
    params(("token" = String, Query, description = "Share token")),
    responses((status = 200, description = "Document info", body = ShareDocumentResponse))
)]
pub async fn validate_share_token(
    State(ctx): State<AppContext>,
    Query(query): Query<ShareTokenQuery>,
) -> Result<Json<ShareDocumentResponse>, StatusCode> {
    let service = ctx.share_service();
    let res = service
        .validate_token(&query.token)
        .await
        .map_err(map_share_error)?;
    let out: ShareDocumentResponse = res.map(Into::into).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(out))
}

// ---- List active shares for current user ----
#[derive(Debug, Serialize, ToSchema)]
pub struct ActiveShareItem {
    pub id: Uuid,
    pub token: String,
    pub permission: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub document_id: Uuid,
    pub document_title: String,
    /// 'document' or 'folder'
    pub document_type: String,
    pub url: String,
    pub parent_share_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/shares/active",
    tag = "Sharing",
    responses((status = 200, description = "Active shares", body = [ActiveShareItem]))
)]
pub async fn list_active_shares(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
) -> Result<Json<Vec<ActiveShareItem>>, StatusCode> {
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
    let service = ctx.share_service();
    let items: Vec<ActiveShareItemDto> = service
        .list_active(workspace_id, &permissions)
        .await
        .map_err(map_share_error)?;
    let base = frontend_base(&ctx.cfg);
    let out: Vec<ActiveShareItem> = items
        .into_iter()
        .map(|r| {
            let url = build_share_url(&base, &r.document_type, r.document_id, &r.token);
            ActiveShareItem {
                id: r.id,
                token: r.token,
                permission: r.permission,
                expires_at: r.expires_at,
                created_at: r.created_at,
                document_id: r.document_id,
                document_title: r.document_title,
                document_type: r.document_type,
                url,
                parent_share_id: r.parent_share_id,
            }
        })
        .collect();
    Ok(Json(out))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ShareBrowseTreeItem {
    pub id: Uuid,
    pub title: String,
    pub parent_id: Option<Uuid>,
    #[schema(example = "document")]
    pub r#type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ShareBrowseResponse {
    pub tree: Vec<ShareBrowseTreeItem>,
}

impl From<ShareBrowseTreeItemDto> for ShareBrowseTreeItem {
    fn from(t: ShareBrowseTreeItemDto) -> Self {
        ShareBrowseTreeItem {
            id: t.id,
            title: t.title,
            parent_id: t.parent_id,
            r#type: t.r#type,
            created_at: t.created_at,
            updated_at: t.updated_at,
        }
    }
}

impl From<ShareBrowseResponseDto> for ShareBrowseResponse {
    fn from(d: ShareBrowseResponseDto) -> Self {
        ShareBrowseResponse {
            tree: d.tree.into_iter().map(Into::into).collect(),
        }
    }
}

#[utoipa::path(get, path = "/api/shares/browse", tag = "Sharing",
    params(("token" = String, Query, description = "Share token")),
    responses((status = 200, description = "Share tree", body = ShareBrowseResponse)))]
pub async fn browse_share(
    State(ctx): State<AppContext>,
    Query(query): Query<ShareTokenQuery>,
) -> Result<Json<ShareBrowseResponse>, StatusCode> {
    let service = ctx.share_service();
    let res = service
        .browse_share(&query.token)
        .await
        .map_err(map_share_error)?;
    let out: ShareBrowseResponse = res.map(Into::into).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(out))
}

// Helper function to validate share token (for WebSocket)
// validate_share_token_for_doc was moved to `access` layer via ShareAccessPort; no local implementation here

pub fn routes(ctx: AppContext) -> Router {
    Router::new()
        .route("/shares", post(create_share))
        .route("/shares/browse", get(browse_share))
        .route("/shares/validate", get(validate_share_token))
        .route("/shares/documents/:id", get(list_document_shares))
        .route("/shares/applicable", get(list_applicable_shares))
        .route(
            "/shares/folders/:token/materialize",
            post(materialize_folder_share),
        )
        .route("/shares/active", get(list_active_shares))
        .route("/shares/:token", delete(delete_share))
        .with_state(ctx)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MaterializeResponse {
    pub created: i64,
}

#[utoipa::path(post, path = "/api/shares/folders/{token}/materialize", tag = "Sharing",
    params(("token" = String, Path, description = "Folder share token")),
    responses((status = 200, description = "Created doc shares", body = MaterializeResponse))
)]
pub async fn materialize_folder_share(
    State(ctx): State<AppContext>,
    bearer: Bearer,
    headers: HeaderMap,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Result<Json<MaterializeResponse>, StatusCode> {
    let bearer_token = bearer.0.clone();
    let sub = auth::validate_bearer_public(&ctx, bearer).await?;
    let user_id = uuid::Uuid::parse_str(&sub).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let workspace_id = workspace_scope::resolve_active_workspace_id(
        &ctx,
        &headers,
        Some(bearer_token.as_str()),
        user_id,
    )
    .await?;
    let permissions =
        workspace_scope::resolve_workspace_permissions(&ctx, workspace_id, user_id).await?;
    let service = ctx.share_service();
    let meta = service
        .share_document_meta(&token)
        .await
        .map_err(map_share_error)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if meta.workspace_id != workspace_id {
        return Err(StatusCode::FORBIDDEN);
    }
    let actor = access::Actor::User(user_id);
    ctx.authorization()
        .require_edit(&actor, meta.document_id)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let created = service
        .materialize_folder_share(workspace_id, user_id, &permissions, &token)
        .await
        .map_err(map_share_error)?;
    Ok(Json(MaterializeResponse { created }))
}
