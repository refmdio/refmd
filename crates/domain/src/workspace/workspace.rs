//! Workspace entity

use chrono::{DateTime, Utc};

use super::value_objects::{Slug, WorkspaceId};
use crate::identity::UserId;

/// Workspace - container for documents
#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub slug: Slug,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub owner_id: UserId,
    /// Minimum KEK version allowed for encryption operations
    /// Keys with versions below this are rejected (used after key rotation)
    pub min_kek_version: i32,
    /// Whether the workspace needs KEK rotation (e.g., after device revocation)
    pub needs_kek_rotation: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Workspace {
    /// Create a new workspace
    pub fn new(name: String, slug: Slug, owner_id: UserId) -> Self {
        let now = Utc::now();
        Self {
            id: WorkspaceId::new(),
            name,
            slug,
            description: None,
            icon: None,
            owner_id,
            min_kek_version: 1,
            needs_kek_rotation: false,
            created_at: now,
            updated_at: now,
        }
    }

    /// Update the minimum KEK version (used after key rotation)
    pub fn set_min_kek_version(&mut self, version: i32) {
        self.min_kek_version = version;
        self.updated_at = Utc::now();
    }

    /// Mark workspace as needing KEK rotation (e.g., after device revocation)
    pub fn mark_needs_kek_rotation(&mut self) {
        self.needs_kek_rotation = true;
        self.updated_at = Utc::now();
    }

    /// Clear the KEK rotation flag (after rotation is complete)
    pub fn clear_kek_rotation_flag(&mut self) {
        self.needs_kek_rotation = false;
        self.updated_at = Utc::now();
    }

    /// Update workspace details
    pub fn update(
        &mut self,
        name: Option<String>,
        description: Option<Option<String>>,
        icon: Option<Option<String>>,
    ) {
        if let Some(n) = name {
            self.name = n;
        }
        if let Some(d) = description {
            self.description = d;
        }
        if let Some(i) = icon {
            self.icon = i;
        }
        self.updated_at = Utc::now();
    }

    /// Touch updated_at timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}
