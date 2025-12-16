use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use application::contracts::public::PublicDocumentSummaryDto;

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
