use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PublicDocumentSummaryDto {
    pub id: Uuid,
    pub title: String,
    pub updated_at: DateTime<Utc>,
    pub published_at: DateTime<Utc>,
}
