//! Workspace role permission override entity

use super::value_objects::RoleId;

/// A per-role permission override stored in the DB.
///
/// When `granted` is true, the role has this permission (even if the
/// base_role default would deny it, subject to ceiling).
/// When `granted` is false, the permission is explicitly revoked
/// (even if the base_role default would grant it).
#[derive(Debug, Clone)]
pub struct WorkspaceRolePermission {
    pub role_id: RoleId,
    pub permission: String,
    pub granted: bool,
}
