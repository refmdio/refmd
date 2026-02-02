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
            created_at: now,
            updated_at: now,
        }
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
