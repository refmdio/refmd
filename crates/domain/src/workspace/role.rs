//! Workspace role entities

use chrono::{DateTime, Utc};

use super::value_objects::{BaseRole, Permission, RoleId, WorkspaceId};

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

    /// Create the default admin role
    pub fn admin(workspace_id: WorkspaceId) -> Self {
        Self::new(workspace_id, "Admin".to_string(), BaseRole::Admin, false)
    }

    /// Create the default editor role
    pub fn editor(workspace_id: WorkspaceId) -> Self {
        Self::new(workspace_id, "Editor".to_string(), BaseRole::Editor, true)
    }

    /// Create the default viewer role
    pub fn viewer(workspace_id: WorkspaceId) -> Self {
        Self::new(workspace_id, "Viewer".to_string(), BaseRole::Viewer, false)
    }

    /// Check if this is an owner role
    pub fn is_owner(&self) -> bool {
        self.base_role == BaseRole::Owner
    }

    /// Check if this is an admin role
    pub fn is_admin(&self) -> bool {
        self.base_role == BaseRole::Admin
    }
}

/// Workspace role permission
#[derive(Debug, Clone)]
pub struct WorkspaceRolePermission {
    pub role_id: RoleId,
    pub permission: Permission,
    pub granted: bool,
}

impl WorkspaceRolePermission {
    /// Create a new role permission
    pub fn new(role_id: RoleId, permission: Permission, granted: bool) -> Self {
        Self {
            role_id,
            permission,
            granted,
        }
    }

    /// Grant permission
    pub fn grant(role_id: RoleId, permission: Permission) -> Self {
        Self::new(role_id, permission, true)
    }

    /// Deny permission
    pub fn deny(role_id: RoleId, permission: Permission) -> Self {
        Self::new(role_id, permission, false)
    }
}
