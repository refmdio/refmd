//! Workspace permission catalog and default grant matrix
//!
//! Defines the 11-permission catalog with ceiling enforcement and
//! base_role default grants. DB overrides (WorkspaceRolePermission)
//! can narrow or widen permissions within the ceiling.

use super::value_objects::BaseRole;

// =============================================================================
// Permission catalog constants
// =============================================================================

pub const DOCUMENT_READ: &str = "document:read";
pub const DOCUMENT_WRITE: &str = "document:write";
pub const DOCUMENT_DELETE: &str = "document:delete";
pub const DOCUMENT_ARCHIVE: &str = "document:archive";
pub const WORKSPACE_UPDATE: &str = "workspace:update";
pub const WORKSPACE_DELETE: &str = "workspace:delete";
pub const MEMBER_LIST: &str = "member:list";
pub const MEMBER_INVITE: &str = "member:invite";
pub const MEMBER_CHANGE_ROLE: &str = "member:change_role";
pub const MEMBER_REMOVE: &str = "member:remove";
pub const ROLE_MANAGE: &str = "role:manage";

/// All known permissions (for validation)
pub const ALL_PERMISSIONS: &[&str] = &[
    DOCUMENT_READ,
    DOCUMENT_WRITE,
    DOCUMENT_DELETE,
    DOCUMENT_ARCHIVE,
    WORKSPACE_UPDATE,
    WORKSPACE_DELETE,
    MEMBER_LIST,
    MEMBER_INVITE,
    MEMBER_CHANGE_ROLE,
    MEMBER_REMOVE,
    ROLE_MANAGE,
];

/// Check if a permission string is valid (in the catalog)
pub fn is_valid_permission(permission: &str) -> bool {
    ALL_PERMISSIONS.contains(&permission)
}

// =============================================================================
// Ceiling: maximum base_role that can hold each permission
// =============================================================================

/// Returns the highest (least-privileged) base_role that can ever hold this
/// permission. A role with a base_role *above* (more privileged than) the
/// ceiling can also hold it; one *below* can never hold it regardless of
/// DB overrides.
///
/// Returns `None` for unknown permissions.
pub fn ceiling(permission: &str) -> Option<BaseRole> {
    match permission {
        DOCUMENT_READ => Some(BaseRole::Viewer),
        DOCUMENT_WRITE => Some(BaseRole::Editor),
        DOCUMENT_DELETE => Some(BaseRole::Admin),
        DOCUMENT_ARCHIVE => Some(BaseRole::Editor),
        WORKSPACE_UPDATE => Some(BaseRole::Admin),
        WORKSPACE_DELETE => Some(BaseRole::Owner),
        MEMBER_LIST => Some(BaseRole::Viewer),
        MEMBER_INVITE => Some(BaseRole::Admin),
        MEMBER_CHANGE_ROLE => Some(BaseRole::Admin),
        MEMBER_REMOVE => Some(BaseRole::Admin),
        ROLE_MANAGE => Some(BaseRole::Admin),
        _ => None,
    }
}

// =============================================================================
// Base-role privilege ordering
// =============================================================================

/// Numeric privilege level (higher = more privileged)
pub fn privilege_level(role: BaseRole) -> u8 {
    match role {
        BaseRole::Viewer => 0,
        BaseRole::Editor => 1,
        BaseRole::Admin => 2,
        BaseRole::Owner => 3,
    }
}

/// True if `role` is at or above `ceiling_role` in privilege
pub fn is_at_or_above(role: BaseRole, ceiling_role: BaseRole) -> bool {
    privilege_level(role) >= privilege_level(ceiling_role)
}

// =============================================================================
// Default grant matrix
// =============================================================================

/// Default grant for a base_role + permission pair (no DB override).
pub fn default_grant(base_role: BaseRole, permission: &str) -> bool {
    match permission {
        // document:read — all roles
        DOCUMENT_READ => true,
        // document:write — Owner, Admin, Editor
        DOCUMENT_WRITE => matches!(base_role, BaseRole::Owner | BaseRole::Admin | BaseRole::Editor),
        // document:delete — Owner, Admin
        DOCUMENT_DELETE => matches!(base_role, BaseRole::Owner | BaseRole::Admin),
        // document:archive — Owner, Admin, Editor
        DOCUMENT_ARCHIVE => matches!(base_role, BaseRole::Owner | BaseRole::Admin | BaseRole::Editor),
        // workspace:update — Owner, Admin
        WORKSPACE_UPDATE => matches!(base_role, BaseRole::Owner | BaseRole::Admin),
        // workspace:delete — Owner only
        WORKSPACE_DELETE => matches!(base_role, BaseRole::Owner),
        // member:list — all roles
        MEMBER_LIST => true,
        // member:invite — Owner, Admin
        MEMBER_INVITE => matches!(base_role, BaseRole::Owner | BaseRole::Admin),
        // member:change_role — Owner, Admin
        MEMBER_CHANGE_ROLE => matches!(base_role, BaseRole::Owner | BaseRole::Admin),
        // member:remove — Owner, Admin
        MEMBER_REMOVE => matches!(base_role, BaseRole::Owner | BaseRole::Admin),
        // role:manage — Owner, Admin
        ROLE_MANAGE => matches!(base_role, BaseRole::Owner | BaseRole::Admin),
        // Unknown permission — deny
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owner_has_all_permissions() {
        for &perm in ALL_PERMISSIONS {
            assert!(default_grant(BaseRole::Owner, perm), "Owner should have {perm}");
        }
    }

    #[test]
    fn test_admin_permissions() {
        for &perm in ALL_PERMISSIONS {
            let expected = perm != WORKSPACE_DELETE;
            assert_eq!(default_grant(BaseRole::Admin, perm), expected, "Admin check for {perm}");
        }
    }

    #[test]
    fn test_editor_permissions() {
        let editor_perms = [DOCUMENT_READ, DOCUMENT_WRITE, DOCUMENT_ARCHIVE, MEMBER_LIST];
        for &perm in ALL_PERMISSIONS {
            let expected = editor_perms.contains(&perm);
            assert_eq!(default_grant(BaseRole::Editor, perm), expected, "Editor check for {perm}");
        }
    }

    #[test]
    fn test_viewer_permissions() {
        let viewer_perms = [DOCUMENT_READ, MEMBER_LIST];
        for &perm in ALL_PERMISSIONS {
            let expected = viewer_perms.contains(&perm);
            assert_eq!(default_grant(BaseRole::Viewer, perm), expected, "Viewer check for {perm}");
        }
    }

    #[test]
    fn test_ceiling_enforcement() {
        // Viewer ceiling for document:read means Viewer-level can hold it
        assert_eq!(ceiling(DOCUMENT_READ), Some(BaseRole::Viewer));
        // Admin ceiling for document:delete means only Admin+ can hold it
        assert_eq!(ceiling(DOCUMENT_DELETE), Some(BaseRole::Admin));
        // Owner ceiling for workspace:delete means only Owner can hold it
        assert_eq!(ceiling(WORKSPACE_DELETE), Some(BaseRole::Owner));
    }

    #[test]
    fn test_is_at_or_above() {
        assert!(is_at_or_above(BaseRole::Owner, BaseRole::Viewer));
        assert!(is_at_or_above(BaseRole::Admin, BaseRole::Admin));
        assert!(!is_at_or_above(BaseRole::Viewer, BaseRole::Admin));
        assert!(!is_at_or_above(BaseRole::Editor, BaseRole::Admin));
    }

    #[test]
    fn test_unknown_permission_denied() {
        assert!(!default_grant(BaseRole::Owner, "unknown:perm"));
        assert!(ceiling("unknown:perm").is_none());
    }

    #[test]
    fn test_backward_compat_read_write_delete() {
        // Ensure old Read/Write/Delete semantics are preserved
        // Read: all roles
        assert!(default_grant(BaseRole::Viewer, DOCUMENT_READ));
        // Write: Owner, Admin, Editor
        assert!(default_grant(BaseRole::Editor, DOCUMENT_WRITE));
        assert!(!default_grant(BaseRole::Viewer, DOCUMENT_WRITE));
        // Delete: Owner, Admin
        assert!(default_grant(BaseRole::Admin, DOCUMENT_DELETE));
        assert!(!default_grant(BaseRole::Editor, DOCUMENT_DELETE));
    }
}
