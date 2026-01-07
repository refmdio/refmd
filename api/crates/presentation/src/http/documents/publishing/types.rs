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
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PublishResponse {
    pub slug: String,
    pub public_url: String,
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
