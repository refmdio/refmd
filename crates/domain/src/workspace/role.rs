//! Workspace role entities

use chrono::{DateTime, Utc};

use super::value_objects::{BaseRole, RoleId, WorkspaceId};

/// Workspace role
#[derive(Debug, Clone)]
pub struct WorkspaceRole {
    pub id: RoleId,
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub base_role: BaseRole,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
}

impl WorkspaceRole {
    /// Create a new workspace role
    pub fn new(
        workspace_id: WorkspaceId,
        name: String,
        base_role: BaseRole,
        is_default: bool,
    ) -> Self {
        Self {
            id: RoleId::new(),
            workspace_id,
            name,
            base_role,
            is_default,
            created_at: Utc::now(),
        }
    }

    /// Create the default owner role
    pub fn owner(workspace_id: WorkspaceId) -> Self {
        Self::new(workspace_id, "Owner".to_string(), BaseRole::Owner, false)
    }

    /// Create the default editor role
    pub fn editor(workspace_id: WorkspaceId) -> Self {
        Self::new(workspace_id, "Editor".to_string(), BaseRole::Editor, true)
    }

    /// Create the default viewer role
    pub fn viewer(workspace_id: WorkspaceId) -> Self {
        Self::new(workspace_id, "Viewer".to_string(), BaseRole::Viewer, false)
    }

}

