use base64::Engine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::context::PresentationConfig;
use application::core::services::errors::ServiceError;
use application::documents::dtos::{
    ActiveShareItemDto, ApplicableShareDto, ShareBrowseResponseDto, ShareBrowseTreeItemDto,
    ShareDocumentDto, ShareItemDto, ShareMountDto,
};
use domain::documents::doc_type::{DOC_TYPE_DOCUMENT, DOC_TYPE_FOLDER};

pub fn frontend_base(cfg: &PresentationConfig) -> String {
    cfg.frontend_url
        .clone()
        .unwrap_or_else(|| "http://localhost:3000".into())
}

pub fn build_share_url(base: &str, document_type: &str, document_id: Uuid, token: &str) -> String {
    let base = base.trim_end_matches('/');
    if document_type == DOC_TYPE_FOLDER {
        format!("{}/share/{}", base, token)
    } else {
        format!("{}/document/{}?token={}", base, document_id, token)
    }
}

pub fn share_scope(document_type: &str) -> String {
    if document_type == DOC_TYPE_FOLDER {
        DOC_TYPE_FOLDER.to_string()
    } else {
        DOC_TYPE_DOCUMENT.to_string()
    }
}

pub fn map_share_error(err: ServiceError) -> crate::http::error::ApiError {
    crate::http::error::map_service_error(err, "share_service_error")
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateShareRequest {
    pub document_id: Uuid,
    pub permission: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    // E2EE fields - encrypted DEK for share access
    /// Base64 encoded encrypted DEK (encrypted with share key derived from password)
    #[serde(default)]
    #[schema(value_type = Option<String>, format = "byte")]
    pub encrypted_dek: Option<String>,
    /// Base64 encoded salt for key derivation
    #[serde(default)]
    #[schema(value_type = Option<String>, format = "byte")]
    pub salt: Option<String>,
    /// KDF parameters (e.g., Argon2id settings)
    #[serde(default)]
    pub kdf_params: Option<serde_json::Value>,
    /// Base64 encoded share key encrypted with creator's KEK (for URL recovery)
    #[serde(default)]
    #[schema(value_type = Option<String>, format = "byte")]
    pub creator_encrypted_share_key: Option<String>,
    /// Base64 encoded nonce for creator_encrypted_share_key
    #[serde(default)]
    #[schema(value_type = Option<String>, format = "byte")]
    pub creator_share_key_nonce: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateShareResponse {
    pub token: String,
    pub url: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShareItem {
    pub id: Uuid,
    pub token: String,
    pub permission: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub url: String,
    pub scope: String,
    pub parent_share_id: Option<Uuid>,
    /// Base64 encoded share key encrypted with creator's KEK (for URL recovery)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub creator_encrypted_share_key: Option<String>,
    /// Base64 encoded nonce for creator_encrypted_share_key
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub creator_share_key_nonce: Option<String>,
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
#[serde(rename_all = "camelCase")]
pub struct ShareDocumentResponse {
    pub id: Uuid,
    pub title: String,
    pub permission: String,
    pub content: Option<String>,
    // E2EE fields
    /// Base64 encoded encrypted DEK (encrypted with share key)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub encrypted_dek: Option<String>,
    /// Base64 encoded salt for password-protected shares
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub salt: Option<String>,
    /// KDF parameters for password-protected shares
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_params: Option<serde_json::Value>,
}

impl From<ShareDocumentDto> for ShareDocumentResponse {
    fn from(d: ShareDocumentDto) -> Self {
        ShareDocumentResponse {
            id: d.id,
            title: d.title,
            permission: d.permission,
            content: d.content,
            encrypted_dek: None,
            salt: None,
            kdf_params: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ShareTokenQuery {
    pub token: String,
}

/// Response for share salt challenge (for password-protected shares)
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ShareSaltResponse {
    /// Whether this share is password-protected
    pub password_protected: bool,
    /// Base64 encoded salt for key derivation (only present if password-protected)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, format = "byte")]
    pub salt: Option<String>,
    /// KDF parameters for key derivation (only present if password-protected)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_params: Option<serde_json::Value>,
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
            creator_encrypted_share_key,
            creator_share_key_nonce,
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
            creator_encrypted_share_key: creator_encrypted_share_key
                .map(|v| base64::engine::general_purpose::STANDARD.encode(&v)),
            creator_share_key_nonce: creator_share_key_nonce
                .map(|v| base64::engine::general_purpose::STANDARD.encode(&v)),
        }
    }
}

pub use axum::http::StatusCode;
