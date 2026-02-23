//! Revoke invitation command
//!
//! Revokes a workspace invitation. Requires PoP + member:invite permission.

use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use domain::identity::UserId;
use domain::workspace::{
    InvitationId, WorkspaceId, WorkspaceInvitationRepository, WorkspaceMemberRepository,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository, permission,
};
use std::sync::Arc;
use thiserror::Error;

/// Revoke invitation command
#[derive(Debug)]
pub struct RevokeInvitationCommand {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub invitation_id: InvitationId,
}

/// Revoke invitation error
#[derive(Debug, Error)]
pub enum RevokeInvitationError<
    MR: std::error::Error,
    RR: std::error::Error,
    RPR: std::error::Error,
    IR: std::error::Error,
> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("invitation not found or already revoked")]
    NotFound,

    #[error("invitation repository error: {0}")]
    InvitationRepository(IR),
}

crate::types::impl_app_error!(
    [MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error, IR: std::error::Error]
    RevokeInvitationError<MR, RR, RPR, IR>,
    not_found: [
        RevokeInvitationError::NotFound,
        RevokeInvitationError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        RevokeInvitationError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
);

/// Revoke invitation handler
pub struct RevokeInvitationHandler<MR: ?Sized, RR: ?Sized, RPR: ?Sized, IR: ?Sized> {
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    invitation_repo: Arc<IR>,
}

impl<MR: ?Sized, RR: ?Sized, RPR: ?Sized, IR: ?Sized>
    RevokeInvitationHandler<MR, RR, RPR, IR>
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
        command: RevokeInvitationCommand,
    ) -> Result<(), RevokeInvitationError<MR::Error, RR::Error, RPR::Error, IR::Error>> {
        // 1. Permission check (member:invite)
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.workspace_id,
            command.user_id,
            permission::MEMBER_INVITE,
        )
        .await
        .map_err(RevokeInvitationError::WorkspaceAccess)?;

        // 2. Atomic revoke: UPDATE WHERE workspace_id matches AND not already revoked
        let revoked = self
            .invitation_repo
            .revoke(command.invitation_id, command.workspace_id)
            .await
            .map_err(RevokeInvitationError::InvitationRepository)?;

        if !revoked {
            return Err(RevokeInvitationError::NotFound);
        }

        Ok(())
    }
}
