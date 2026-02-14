//! Workspace permission checking
//!
//! Defines permissions and role-based access control for workspaces.

use super::value_objects::BaseRole;

/// Workspace permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspacePermission {
    /// View workspace and documents
    Read,
    /// Create and edit documents
    Write,
    /// Delete documents
    Delete,
}

impl WorkspacePermission {
    /// Check if a base role has this permission
    pub fn is_allowed_for(&self, role: BaseRole) -> bool {
        match self {
            // Read: all roles
            WorkspacePermission::Read => true,

            // Write: owner, admin, editor
            WorkspacePermission::Write => {
                matches!(role, BaseRole::Owner | BaseRole::Admin | BaseRole::Editor)
            }

            // Delete: owner, admin
            WorkspacePermission::Delete => matches!(role, BaseRole::Owner | BaseRole::Admin),
        }
    }
}

/// Check if a user with the given base role can perform an action
pub fn can_perform(role: BaseRole, permission: WorkspacePermission) -> bool {
    permission.is_allowed_for(role)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owner_permissions() {
        assert!(can_perform(BaseRole::Owner, WorkspacePermission::Read));
        assert!(can_perform(BaseRole::Owner, WorkspacePermission::Write));
        assert!(can_perform(BaseRole::Owner, WorkspacePermission::Delete));
    }

    #[test]
    fn test_admin_permissions() {
        assert!(can_perform(BaseRole::Admin, WorkspacePermission::Read));
        assert!(can_perform(BaseRole::Admin, WorkspacePermission::Write));
        assert!(can_perform(BaseRole::Admin, WorkspacePermission::Delete));
    }

    #[test]
    fn test_editor_permissions() {
        assert!(can_perform(BaseRole::Editor, WorkspacePermission::Read));
        assert!(can_perform(BaseRole::Editor, WorkspacePermission::Write));
        assert!(!can_perform(BaseRole::Editor, WorkspacePermission::Delete));
    }

    #[test]
    fn test_viewer_permissions() {
        assert!(can_perform(BaseRole::Viewer, WorkspacePermission::Read));
        assert!(!can_perform(BaseRole::Viewer, WorkspacePermission::Write));
        assert!(!can_perform(BaseRole::Viewer, WorkspacePermission::Delete));
    }
}
