//! Delete workspace command
//!
//! Permanently deletes a workspace and all associated data.
//! Requires workspace:delete permission (Owner only by default).

use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspaceRepository,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository, permission,
};
use std::sync::Arc;
use thiserror::Error;

/// Delete workspace command
#[derive(Debug)]
pub struct DeleteWorkspaceCommand {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
}

/// Delete workspace error
#[derive(Debug, Error)]
pub enum DeleteWorkspaceError<
    WR: std::error::Error,
    MR: std::error::Error,
    RR: std::error::Error,
    RPR: std::error::Error,
> {
    #[error("workspace not found")]
    WorkspaceNotFound,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),
}

crate::types::impl_app_error!(
    [WR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    DeleteWorkspaceError<WR, MR, RR, RPR>,
    not_found: [
        DeleteWorkspaceError::WorkspaceNotFound,
        DeleteWorkspaceError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        DeleteWorkspaceError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
);

/// Delete workspace handler
pub struct DeleteWorkspaceHandler<WR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    workspace_repo: Arc<WR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
}

impl<WR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> DeleteWorkspaceHandler<WR, MR, RR, RPR>
where
    WR: WorkspaceRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
{
    pub fn new(
        workspace_repo: Arc<WR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
    ) -> Self {
        Self {
            workspace_repo,
            member_repo,
            role_repo,
            role_perm_repo,
        }
    }

    pub async fn handle(
        &self,
        command: DeleteWorkspaceCommand,
    ) -> Result<(), DeleteWorkspaceError<WR::Error, MR::Error, RR::Error, RPR::Error>> {
        // 1. Permission check (workspace:delete = Owner only)
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.workspace_id,
            command.user_id,
            permission::WORKSPACE_DELETE,
        )
        .await
        .map_err(DeleteWorkspaceError::WorkspaceAccess)?;

        // 2. Verify workspace exists.
        //    Note: there is a TOCTOU window between this check and the DELETE below.
        //    If the workspace is concurrently deleted between steps 2 and 3, the DELETE
        //    will affect 0 rows and the handler returns Ok(()) (idempotent deletion).
        //    This is acceptable because:
        //    (a) The desired outcome (workspace deleted) is achieved regardless.
        //    (b) The permission check in step 1 already verified access.
        //    (c) Returning 204 for an already-deleted workspace is safe — the caller
        //        gets the same functional result.
        let _workspace = self
            .workspace_repo
            .find_by_id(command.workspace_id)
            .await
            .map_err(DeleteWorkspaceError::WorkspaceRepository)?
            .ok_or(DeleteWorkspaceError::WorkspaceNotFound)?;

        // 3. Delete workspace (cascading deletes handled by DB)
        self.workspace_repo
            .delete(command.workspace_id)
            .await
            .map_err(DeleteWorkspaceError::WorkspaceRepository)?;

        Ok(())
    }
}
