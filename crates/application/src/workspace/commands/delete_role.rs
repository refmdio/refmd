//! Delete workspace role command
//!
//! Deletes a custom role from a workspace. Requires role:manage permission.
//! Cannot delete roles that are marked as default or have members assigned.
//! Returns invalidated_invitation_count per design doc.

use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use domain::identity::UserId;
use domain::workspace::{
    BaseRole, RoleId, WorkspaceId, WorkspaceInvitationRepository, WorkspaceMemberRepository,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository, WorkspaceRoleRepositoryErrorClassifier,
    permission,
};
use std::sync::Arc;
use thiserror::Error;

/// Delete role command
#[derive(Debug)]
pub struct DeleteRoleCommand {
    pub workspace_id: WorkspaceId,
    pub role_id: RoleId,
    pub user_id: UserId,
}

/// Delete role result
#[derive(Debug)]
pub struct DeleteRoleResult {
    /// Approximate number of invitations invalidated by the role deletion (role_id SET NULL
    /// by FK cascade). This count is taken before the DELETE and may slightly differ from
    /// the actual number of affected rows due to concurrent invitation creation/deletion.
    /// The count is informational for the API response; the FK cascade is the source of truth.
    pub invalidated_invitation_count: i64,
}

/// Delete role error
#[derive(Debug, Error)]
pub enum DeleteRoleError<
    MR: std::error::Error,
    RR: std::error::Error,
    RPR: std::error::Error,
    IR: std::error::Error,
> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("role not found")]
    RoleNotFound,

    #[error("role does not belong to this workspace")]
    RoleWorkspaceMismatch,

    #[error("cannot delete the Owner role")]
    CannotDeleteOwnerRole,

    #[error("cannot delete the default role — assign another role as default first")]
    CannotDeleteDefaultRole,

    #[error("cannot delete role: members are still assigned to it")]
    RoleHasMembers,

    #[error("cannot delete the default role — the role became default concurrently")]
    RoleBecameDefault,

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),

    #[error("role permission repository error: {0}")]
    RolePermissionRepository(RPR),

    #[error("invitation repository error: {0}")]
    InvitationRepository(IR),
}

crate::types::impl_app_error!(
    [MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error, IR: std::error::Error]
    DeleteRoleError<MR, RR, RPR, IR>,
    not_found: [
        DeleteRoleError::RoleNotFound,
        DeleteRoleError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        DeleteRoleError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
        DeleteRoleError::RoleWorkspaceMismatch,
    ],
    invalid_input: [
        DeleteRoleError::CannotDeleteOwnerRole,
        DeleteRoleError::CannotDeleteDefaultRole,
    ],
    conflict: [
        DeleteRoleError::RoleHasMembers,
        DeleteRoleError::RoleBecameDefault,
    ],
);

/// Delete role handler
pub struct DeleteRoleHandler<MR: ?Sized, RR: ?Sized, RPR: ?Sized, IR: ?Sized> {
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    invitation_repo: Arc<IR>,
}

impl<MR: ?Sized, RR: ?Sized, RPR: ?Sized, IR: ?Sized> DeleteRoleHandler<MR, RR, RPR, IR>
where
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
    IR: WorkspaceInvitationRepository,
{
    pub fn new(
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
        invitation_repo: Arc<IR>,
    ) -> Self {
        Self {
            member_repo,
            role_repo,
            role_perm_repo,
            invitation_repo,
        }
    }

    pub async fn handle(
        &self,
        command: DeleteRoleCommand,
    ) -> Result<DeleteRoleResult, DeleteRoleError<MR::Error, RR::Error, RPR::Error, IR::Error>> {
        // 1. Permission check
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.workspace_id,
            command.user_id,
            permission::ROLE_MANAGE,
        )
        .await
        .map_err(DeleteRoleError::WorkspaceAccess)?;

        // 2. Load role
        let role = self
            .role_repo
            .find_by_id(command.role_id)
            .await
            .map_err(DeleteRoleError::RoleRepository)?
            .ok_or(DeleteRoleError::RoleNotFound)?;

        // 3. Verify role belongs to workspace
        if role.workspace_id != command.workspace_id {
            return Err(DeleteRoleError::RoleWorkspaceMismatch);
        }

        // 4. Cannot delete Owner role
        if role.base_role == BaseRole::Owner {
            return Err(DeleteRoleError::CannotDeleteOwnerRole);
        }

        // 5. Cannot delete default role
        if role.is_default {
            return Err(DeleteRoleError::CannotDeleteDefaultRole);
        }

        // 6. Check no members are assigned to this role
        let members = self
            .member_repo
            .find_by_workspace_id(command.workspace_id)
            .await
            .map_err(DeleteRoleError::MemberRepository)?;

        if members.iter().any(|m| m.role_id == command.role_id) {
            return Err(DeleteRoleError::RoleHasMembers);
        }

        // 7. Count invitations that will be invalidated (approximate, taken before delete).
        //    Due to the non-atomic window between this count and the DELETE at step 8,
        //    the actual number of SET NULL'd invitations may differ slightly. This is
        //    acceptable as the count is informational for the API response — the FK
        //    cascade is the authoritative mechanism that invalidates invitations.
        let invalidated_invitation_count = self
            .invitation_repo
            .count_by_role_id(command.workspace_id, command.role_id)
            .await
            .map_err(DeleteRoleError::InvitationRepository)?;

        // 8. Delete role — FK ON DELETE CASCADE on workspace_role_permissions
        //    automatically removes permission overrides, and FK ON DELETE SET NULL
        //    on workspace_invitations sets role_id to NULL for affected invitations.
        //
        //    The pre-check at step 6 already validates no members are assigned.
        //    If a TOCTOU race causes an FK violation here (member assigned between
        //    step 6 and this DELETE), the error classifier maps it to a 409.
        self.role_repo
            .delete(command.role_id, command.workspace_id)
            .await
            .map_err(|e| {
                if e.is_role_became_default() {
                    // Role became default concurrently (is_default=true guard in DELETE).
                    // Pre-check at step 5 passed but a concurrent swap_default made this
                    // role the default between the check and the DELETE.
                    DeleteRoleError::RoleBecameDefault
                } else if e.is_role_in_use() {
                    // Members still assigned (FK violation, 23503). TOCTOU race between
                    // the pre-check at step 6 and this DELETE.
                    DeleteRoleError::RoleHasMembers
                } else if e.is_role_not_found() {
                    DeleteRoleError::RoleNotFound
                } else {
                    DeleteRoleError::RoleRepository(e)
                }
            })?;

        Ok(DeleteRoleResult {
            invalidated_invitation_count,
        })
    }
}
