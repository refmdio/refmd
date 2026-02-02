//! DocumentLink entity

use chrono::{DateTime, Utc};

use super::value_objects::{DocumentId, DocumentLinkId, LinkType};

/// Document link (for backlinks)
#[derive(Debug, Clone)]
pub struct DocumentLink {
    pub id: DocumentLinkId,
    pub source_id: DocumentId,
    pub target_id: DocumentId,
    pub link_type: LinkType,
    pub link_text: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl DocumentLink {
    /// Create a new document link
    pub fn new(
        source_id: DocumentId,
        target_id: DocumentId,
        link_type: LinkType,
        link_text: Option<String>,
    ) -> Self {
        Self {
            id: DocumentLinkId::new(),
            source_id,
            target_id,
            link_type,
            link_text,
            created_at: Utc::now(),
        }
    }

    /// Create a wikilink
    pub fn wikilink(
        source_id: DocumentId,
        target_id: DocumentId,
        link_text: Option<String>,
    ) -> Self {
        Self::new(source_id, target_id, LinkType::wikilink(), link_text)
    }
}
