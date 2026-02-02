//! Workspace entity

use chrono::{DateTime, Utc};

use crate::identity::UserId;
use super::value_objects::{Slug, WorkspaceId};

/// Workspace - container for documents
#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub slug: Slug,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub is_personal: bool,
    pub owner_id: UserId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Workspace {
    /// Create a new workspace
    pub fn new(
        name: String,
        slug: Slug,
        owner_id: UserId,
        is_personal: bool,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: WorkspaceId::new(),
            name,
            slug,
            description: None,
            icon: None,
            is_personal,
            owner_id,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a personal workspace for a user
    pub fn new_personal(name: String, slug: Slug, owner_id: UserId) -> Self {
        Self::new(name, slug, owner_id, true)
    }

    /// Create a team workspace
    pub fn new_team(name: String, slug: Slug, owner_id: UserId) -> Self {
        Self::new(name, slug, owner_id, false)
    }

    /// Update workspace details
    pub fn update(&mut self, name: Option<String>, description: Option<Option<String>>, icon: Option<Option<String>>) {
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
