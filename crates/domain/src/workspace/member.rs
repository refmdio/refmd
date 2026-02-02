//! Workspace member entity

use chrono::{DateTime, Utc};

use super::value_objects::{RoleId, WorkspaceId};
use crate::identity::UserId;

/// Workspace member
#[derive(Debug, Clone)]
pub struct WorkspaceMember {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub role_id: RoleId,
    pub is_default: bool,
    pub joined_at: DateTime<Utc>,
}

impl WorkspaceMember {
    /// Create a new workspace member
    pub fn new(
        workspace_id: WorkspaceId,
        user_id: UserId,
        role_id: RoleId,
        is_default: bool,
    ) -> Self {
        Self {
            workspace_id,
            user_id,
            role_id,
            is_default,
            joined_at: Utc::now(),
        }
    }

    /// Create the owner member (first member of a workspace)
    pub fn new_owner(workspace_id: WorkspaceId, user_id: UserId, owner_role_id: RoleId) -> Self {
        Self::new(workspace_id, user_id, owner_role_id, true)
    }

    /// Change member's role
    pub fn change_role(&mut self, role_id: RoleId) {
        self.role_id = role_id;
    }

    /// Set as default workspace
    pub fn set_default(&mut self, is_default: bool) {
        self.is_default = is_default;
    }
}
