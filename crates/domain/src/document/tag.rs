//! Tag and DocumentTag entities

use super::value_objects::{DocumentId, TagId};
use crate::workspace::WorkspaceId;

/// Tag (workspace scoped)
#[derive(Debug, Clone)]
pub struct Tag {
    pub id: TagId,
    pub workspace_id: WorkspaceId,
    pub name: String,
}

impl Tag {
    /// Create a new tag (id will be set by database)
    pub fn new(workspace_id: WorkspaceId, name: String) -> Self {
        Self {
            id: TagId::new(0), // Will be set by database
            workspace_id,
            name,
        }
    }
}

/// Document tag relation
#[derive(Debug, Clone)]
pub struct DocumentTag {
    pub document_id: DocumentId,
    pub tag_id: TagId,
    pub encrypted_tag: Option<Vec<u8>>,
}

impl DocumentTag {
    /// Create a new document tag
    pub fn new(document_id: DocumentId, tag_id: TagId) -> Self {
        Self {
            document_id,
            tag_id,
            encrypted_tag: None,
        }
    }

    /// Create a new document tag with encrypted tag for E2EE search
    pub fn with_encrypted_tag(
        document_id: DocumentId,
        tag_id: TagId,
        encrypted_tag: Vec<u8>,
    ) -> Self {
        Self {
            document_id,
            tag_id,
            encrypted_tag: Some(encrypted_tag),
        }
    }
}
