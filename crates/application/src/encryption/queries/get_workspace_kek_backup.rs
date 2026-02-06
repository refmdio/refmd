//! Get workspace KEK backup query
//!
//! Retrieves the active KEK backup for a user in a workspace.
//! Requires workspace membership (Read permission minimum).

use domain::encryption::{WorkspaceKekBackup, WorkspaceKekBackupRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
    can_perform,
};
use std::sync::Arc;
use thiserror::Error;

/// Get workspace KEK backup query
#[derive(Debug)]
pub struct GetWorkspaceKekBackupQuery {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
}

/// Get workspace KEK backup result
#[derive(Debug)]
pub struct GetWorkspaceKekBackupResult {
    pub backup: WorkspaceKekBackup,
}

/// Get workspace KEK backup error
#[derive(Debug, Error)]
pub enum GetWorkspaceKekBackupError<BR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
    #[error("KEK backup not found")]
    BackupNotFound,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot access this workspace")]
    PermissionDenied,

    #[error("backup repository error: {0}")]
    BackupRepository(BR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<BR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    GetWorkspaceKekBackupError<BR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, GetWorkspaceKekBackupError::BackupNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            GetWorkspaceKekBackupError::NotMember | GetWorkspaceKekBackupError::PermissionDenied
        )
    }
}

/// Get workspace KEK backup handler
pub struct GetWorkspaceKekBackupHandler<BR: ?Sized, MR, RR> {
    backup_repo: Arc<BR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<BR, MR, RR> GetWorkspaceKekBackupHandler<BR, MR, RR>
where
    BR: WorkspaceKekBackupRepository + ?Sized,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
{
    pub fn new(backup_repo: Arc<BR>, member_repo: Arc<MR>, role_repo: Arc<RR>) -> Self {
        Self {
            backup_repo,
            member_repo,
            role_repo,
        }
    }

    pub async fn handle(
        &self,
        query: GetWorkspaceKekBackupQuery,
    ) -> Result<
        GetWorkspaceKekBackupResult,
        GetWorkspaceKekBackupError<BR::Error, MR::Error, RR::Error>,
    > {
        // 1. Check membership
        let member = self
            .member_repo
            .find_by_workspace_and_user(query.workspace_id, query.user_id)
            .await
            .map_err(GetWorkspaceKekBackupError::MemberRepository)?
            .ok_or(GetWorkspaceKekBackupError::NotMember)?;

        // 2. Get role and check Read permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(GetWorkspaceKekBackupError::RoleRepository)?
            .ok_or(GetWorkspaceKekBackupError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Read) {
            return Err(GetWorkspaceKekBackupError::PermissionDenied);
        }

        // 3. Get active backup
        let backup = self
            .backup_repo
            .find_active_by_workspace_and_user(query.workspace_id, query.user_id)
            .await
            .map_err(GetWorkspaceKekBackupError::BackupRepository)?
            .ok_or(GetWorkspaceKekBackupError::BackupNotFound)?;

        Ok(GetWorkspaceKekBackupResult { backup })
    }
}
