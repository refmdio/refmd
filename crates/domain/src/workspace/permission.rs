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
    /// Invite members
    InviteMembers,
    /// Manage roles and permissions
    ManageRoles,
    /// Delete workspace
    DeleteWorkspace,
    /// Transfer ownership
    TransferOwnership,
}

impl WorkspacePermission {
    /// Check if a base role has this permission
    pub fn is_allowed_for(&self, role: BaseRole) -> bool {
        match self {
            // Read: all roles
            WorkspacePermission::Read => true,

            // Write: owner, admin, editor
            WorkspacePermission::Write => matches!(
                role,
                BaseRole::Owner | BaseRole::Admin | BaseRole::Editor
            ),

            // Delete: owner, admin
            WorkspacePermission::Delete => matches!(role, BaseRole::Owner | BaseRole::Admin),

            // InviteMembers: owner, admin
            WorkspacePermission::InviteMembers => {
                matches!(role, BaseRole::Owner | BaseRole::Admin)
            }

            // ManageRoles: owner, admin
            WorkspacePermission::ManageRoles => matches!(role, BaseRole::Owner | BaseRole::Admin),

            // DeleteWorkspace: owner only
            WorkspacePermission::DeleteWorkspace => matches!(role, BaseRole::Owner),

            // TransferOwnership: owner only
            WorkspacePermission::TransferOwnership => matches!(role, BaseRole::Owner),
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
        assert!(can_perform(BaseRole::Owner, WorkspacePermission::InviteMembers));
        assert!(can_perform(BaseRole::Owner, WorkspacePermission::ManageRoles));
        assert!(can_perform(BaseRole::Owner, WorkspacePermission::DeleteWorkspace));
        assert!(can_perform(BaseRole::Owner, WorkspacePermission::TransferOwnership));
    }

    #[test]
    fn test_admin_permissions() {
        assert!(can_perform(BaseRole::Admin, WorkspacePermission::Read));
        assert!(can_perform(BaseRole::Admin, WorkspacePermission::Write));
        assert!(can_perform(BaseRole::Admin, WorkspacePermission::Delete));
        assert!(can_perform(BaseRole::Admin, WorkspacePermission::InviteMembers));
        assert!(can_perform(BaseRole::Admin, WorkspacePermission::ManageRoles));
        assert!(!can_perform(BaseRole::Admin, WorkspacePermission::DeleteWorkspace));
        assert!(!can_perform(BaseRole::Admin, WorkspacePermission::TransferOwnership));
    }

    #[test]
    fn test_editor_permissions() {
        assert!(can_perform(BaseRole::Editor, WorkspacePermission::Read));
        assert!(can_perform(BaseRole::Editor, WorkspacePermission::Write));
        assert!(!can_perform(BaseRole::Editor, WorkspacePermission::Delete));
        assert!(!can_perform(BaseRole::Editor, WorkspacePermission::InviteMembers));
        assert!(!can_perform(BaseRole::Editor, WorkspacePermission::ManageRoles));
        assert!(!can_perform(BaseRole::Editor, WorkspacePermission::DeleteWorkspace));
        assert!(!can_perform(BaseRole::Editor, WorkspacePermission::TransferOwnership));
    }

    #[test]
    fn test_viewer_permissions() {
        assert!(can_perform(BaseRole::Viewer, WorkspacePermission::Read));
        assert!(!can_perform(BaseRole::Viewer, WorkspacePermission::Write));
        assert!(!can_perform(BaseRole::Viewer, WorkspacePermission::Delete));
        assert!(!can_perform(BaseRole::Viewer, WorkspacePermission::InviteMembers));
        assert!(!can_perform(BaseRole::Viewer, WorkspacePermission::ManageRoles));
        assert!(!can_perform(BaseRole::Viewer, WorkspacePermission::DeleteWorkspace));
        assert!(!can_perform(BaseRole::Viewer, WorkspacePermission::TransferOwnership));
    }
}
