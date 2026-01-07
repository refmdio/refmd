use base64::Engine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use application::documents::dtos::{EncryptedTagEntryDto, EncryptedTagItemDto};

/// Tag entry in list response (E2EE format)
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TagEntry {
    /// Base64 encoded deterministically encrypted tag name
    #[schema(value_type = String, format = "byte")]
    pub encrypted_name: String,
    pub document_count: i64,
}

impl From<EncryptedTagItemDto> for TagEntry {
    fn from(d: EncryptedTagItemDto) -> Self {
        TagEntry {
            encrypted_name: base64::engine::general_purpose::STANDARD.encode(&d.encrypted_tag),
            document_count: d.count,
        }
    }
}

/// Response for GET /api/tags
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListTagsResponse {
    pub tags: Vec<TagEntry>,
}

/// Tag entry in document tags response
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DocumentTagEntry {
    pub id: Uuid,
    /// Base64 encoded deterministically encrypted tag name
    #[schema(value_type = String, format = "byte")]
    pub encrypted_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<EncryptedTagEntryDto> for DocumentTagEntry {
    fn from(d: EncryptedTagEntryDto) -> Self {
        DocumentTagEntry {
            id: d.id,
            encrypted_name: base64::engine::general_purpose::STANDARD.encode(&d.encrypted_tag),
            created_at: d.created_at,
        }
    }
}

/// Response for GET /api/documents/{id}/tags
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DocumentTagsResponse {
    pub tags: Vec<DocumentTagEntry>,
}

/// Single encrypted tag in request
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedTagInput {
    /// Base64 encoded deterministically encrypted tag name
    #[schema(value_type = String, format = "byte")]
    pub encrypted_name: String,
}

/// Request for PUT /api/documents/{id}/tags
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDocumentTagsRequest {
    pub encrypted_tags: Vec<EncryptedTagInput>,
}

/// Query for tag search
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TagSearchQuery {
    /// Optional filter query (Base64 encoded encrypted tag for exact match)
    pub q: Option<String>,
}
