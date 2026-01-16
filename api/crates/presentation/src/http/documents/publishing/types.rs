use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use application::documents::dtos::PublicDocumentSummaryDto;

/// Request to publish a document. For E2EE workspaces, plaintext title and content
/// must be provided so public pages can be rendered without decryption.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublishRequest {
    /// Plaintext title (required for E2EE mode)
    #[serde(default)]
    pub plaintext_title: Option<String>,
    /// Plaintext content (required for E2EE mode)
    #[serde(default)]
    pub plaintext_content: Option<String>,
    /// If true, adds noindex meta tag to prevent search engine indexing (default: true)
    #[serde(default)]
    pub noindex: Option<bool>,
}

/// Request to update noindex setting for a published document
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePublishSettingsRequest {
    /// If true, adds noindex meta tag to prevent search engine indexing
    pub noindex: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PublishResponse {
    pub slug: String,
    pub public_url: String,
    /// If true, noindex meta tag is added to prevent search engine indexing
    pub noindex: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PublicDocumentSummary {
    pub id: Uuid,
    pub title: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub published_at: chrono::DateTime<chrono::Utc>,
}

impl From<PublicDocumentSummaryDto> for PublicDocumentSummary {
    fn from(value: PublicDocumentSummaryDto) -> Self {
        Self {
            id: value.id,
            title: value.title,
            updated_at: value.updated_at,
            published_at: value.published_at,
        }
    }
}

/// Request to upload a public file (decrypted attachment for E2EE documents)
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UploadPublicFileRequest {
    /// Original filename (decrypted)
    pub original_filename: String,
    /// Logical filename as it appears in markdown (e.g., "image.png" from "./attachments/image.png")
    pub logical_filename: String,
    /// MIME type of the file
    pub mime_type: String,
    /// Base64 encoded file content
    pub content: String,
}

/// Public file metadata
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublicFile {
    pub id: Uuid,
    pub file_id: Uuid,
    pub original_filename: String,
    pub logical_filename: String,
    pub mime_type: String,
    pub size: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
