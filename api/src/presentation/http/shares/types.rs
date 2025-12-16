use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::application::dto::shares::{
    ActiveShareItemDto, ApplicableShareDto, ShareBrowseResponseDto, ShareBrowseTreeItemDto,
    ShareDocumentDto, ShareItemDto, ShareMountDto,
};
use crate::application::services::errors::ServiceError;
use crate::presentation::context::PresentationConfig;

pub fn frontend_base(cfg: &PresentationConfig) -> String {
    cfg.frontend_url
        .clone()
        .unwrap_or_else(|| "http://localhost:3000".into())
}

pub fn build_share_url(base: &str, document_type: &str, document_id: Uuid, token: &str) -> String {
    let base = base.trim_end_matches('/');
    if document_type == "folder" {
        format!("{}/share/{}", base, token)
    } else {
        format!("{}/document/{}?token={}", base, document_id, token)
    }
}

pub fn share_scope(document_type: &str) -> String {
    if document_type == "folder" {
        "folder".to_string()
    } else {
        "document".to_string()
    }
}

pub fn map_share_error(err: ServiceError) -> StatusCode {
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

#[derive(Debug, Serialize, ToSchema)]
pub struct ShareItem {
    pub id: Uuid,
    pub token: String,
    pub permission: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub url: String,
    pub scope: String,
    pub parent_share_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct ApplicableQuery {
    pub doc_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicableShareItem {
    pub token: String,
    pub permission: String,
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

#[derive(Debug, Deserialize)]
pub struct ShareTokenQuery {
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ActiveShareItem {
    pub id: Uuid,
    pub token: String,
    pub permission: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub document_id: Uuid,
    pub document_title: String,
    pub document_type: String,
    pub url: String,
    pub parent_share_id: Option<Uuid>,
}

impl From<(ActiveShareItemDto, String)> for ActiveShareItem {
    fn from((dto, base): (ActiveShareItemDto, String)) -> Self {
        let url = build_share_url(&base, &dto.document_type, dto.document_id, &dto.token);
        ActiveShareItem {
            id: dto.id,
            token: dto.token,
            permission: dto.permission,
            expires_at: dto.expires_at,
            created_at: dto.created_at,
            document_id: dto.document_id,
            document_title: dto.document_title,
            document_type: dto.document_type,
            url,
            parent_share_id: dto.parent_share_id,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateShareMountRequest {
    pub token: String,
    pub parent_folder_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ShareMountItem {
    pub id: Uuid,
    pub token: String,
    pub target_document_id: Uuid,
    pub target_document_type: String,
    pub target_title: String,
    pub permission: String,
    pub parent_folder_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<ShareMountDto> for ShareMountItem {
    fn from(d: ShareMountDto) -> Self {
        ShareMountItem {
            id: d.id,
            token: d.token,
            target_document_id: d.target_document_id,
            target_document_type: d.target_document_type,
            target_title: d.target_title,
            permission: d.permission,
            parent_folder_id: d.parent_folder_id,
            created_at: d.created_at,
        }
    }
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

#[derive(Debug, Serialize, ToSchema)]
pub struct MaterializeResponse {
    pub created: i64,
}

impl ShareItem {
    pub fn from_dto(base: &str, dto: ShareItemDto) -> Self {
        let ShareItemDto {
            id,
            token,
            permission,
            expires_at,
            document_id,
            document_type,
            parent_share_id,
            ..
        } = dto;
        let url = build_share_url(base, &document_type, document_id, &token);
        ShareItem {
            id,
            token,
            permission,
            expires_at,
            url,
            scope: share_scope(&document_type),
            parent_share_id,
        }
    }
}

pub use axum::http::StatusCode;
