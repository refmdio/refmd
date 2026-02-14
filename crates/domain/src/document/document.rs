//! Document entity

use chrono::{DateTime, Utc};

use super::value_objects::{DocumentId, DocumentType};
use crate::identity::UserId;
use crate::workspace::WorkspaceId;

/// Document
#[derive(Debug, Clone)]
pub struct Document {
    pub id: DocumentId,
    pub workspace_id: WorkspaceId,
    pub parent_id: Option<DocumentId>,
    pub title: String,
    pub encrypted_title: Option<Vec<u8>>,
    pub encrypted_title_nonce: Option<Vec<u8>>,
    pub slug: String,
    pub path: Option<String>,
    pub doc_type: DocumentType,
    pub is_encrypted: bool,
    pub needs_dek_rotation: bool,
    /// Minimum DEK version allowed for content encryption
    /// Updates with key_version below this are rejected (used after key rotation)
    pub min_dek_version: i32,
    pub created_by: Option<UserId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub archived_at: Option<DateTime<Utc>>,
}

impl Document {
    /// Create a new document
    pub fn new(
        workspace_id: WorkspaceId,
        title: String,
        slug: String,
        created_by: Option<UserId>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: DocumentId::new(),
            workspace_id,
            parent_id: None,
            title,
            encrypted_title: None,
            encrypted_title_nonce: None,
            slug,
            path: None,
            doc_type: DocumentType::Document,
            is_encrypted: false,
            needs_dek_rotation: false,
            min_dek_version: 1,
            created_by,
            created_at: now,
            updated_at: now,
            archived_at: None,
        }
    }

    /// Create a new encrypted document
    pub fn new_encrypted(
        workspace_id: WorkspaceId,
        title: String,
        encrypted_title: Vec<u8>,
        encrypted_title_nonce: Vec<u8>,
        slug: String,
        created_by: Option<UserId>,
    ) -> Self {
        let mut doc = Self::new(workspace_id, title, slug, created_by);
        doc.encrypted_title = Some(encrypted_title);
        doc.encrypted_title_nonce = Some(encrypted_title_nonce);
        doc.is_encrypted = true;
        doc
    }

    /// Create a new folder
    pub fn new_folder(
        workspace_id: WorkspaceId,
        title: String,
        slug: String,
        created_by: Option<UserId>,
    ) -> Self {
        let mut doc = Self::new(workspace_id, title, slug, created_by);
        doc.doc_type = DocumentType::Folder;
        doc
    }

    /// Set parent document
    pub fn with_parent(mut self, parent_id: DocumentId) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// Check if document is a folder
    pub fn is_folder(&self) -> bool {
        self.doc_type == DocumentType::Folder
    }

    /// Check if document is archived
    pub fn is_archived(&self) -> bool {
        self.archived_at.is_some()
    }

    /// Archive document
    pub fn archive(&mut self) {
        self.archived_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Unarchive document
    pub fn unarchive(&mut self) {
        self.archived_at = None;
        self.updated_at = Utc::now();
    }

    /// Mark as needing DEK rotation
    pub fn mark_needs_dek_rotation(&mut self) {
        self.needs_dek_rotation = true;
        self.updated_at = Utc::now();
    }

    /// Clear DEK rotation flag
    pub fn clear_dek_rotation_flag(&mut self) {
        self.needs_dek_rotation = false;
        self.updated_at = Utc::now();
    }

    /// Update title
    pub fn set_title(&mut self, title: String) {
        self.title = title;
        self.updated_at = Utc::now();
    }

    /// Update encrypted title
    pub fn set_encrypted_title(&mut self, title: Vec<u8>, nonce: Vec<u8>) {
        self.encrypted_title = Some(title);
        self.encrypted_title_nonce = Some(nonce);
        self.is_encrypted = true;
        self.updated_at = Utc::now();
    }

    /// Update parent document
    pub fn set_parent(&mut self, parent_id: Option<DocumentId>) {
        self.parent_id = parent_id;
        self.updated_at = Utc::now();
    }

    /// Update the minimum DEK version (used after key rotation)
    /// This is monotonic - the value can only increase, never decrease.
    pub fn set_min_dek_version(&mut self, version: i32) {
        if version > self.min_dek_version {
            self.min_dek_version = version;
            self.updated_at = Utc::now();
        }
    }
}
