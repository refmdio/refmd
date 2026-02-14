//! Get workspace KEK backup query
//!
//! Retrieves the active KEK backup for a user in a workspace.
//! Requires workspace membership (Read permission minimum).

use crate::dto::WorkspaceKekBackupDto;
use domain::encryption::WorkspaceKekBackupRepository;
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
};
use std::sync::Arc;

use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
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
    pub backup: WorkspaceKekBackupDto,
}

/// Get workspace KEK backup error
#[derive(Debug, Error)]
pub enum GetWorkspaceKekBackupError<BR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
    #[error("KEK backup not found")]
    BackupNotFound,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR>),

    #[error("backup repository error: {0}")]
    BackupRepository(BR),
}

impl<BR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    crate::types::AppError for GetWorkspaceKekBackupError<BR, MR, RR>
{
    fn is_not_found(&self) -> bool {
        matches!(
            self,
            GetWorkspaceKekBackupError::BackupNotFound
                | GetWorkspaceKekBackupError::WorkspaceAccess(WorkspaceAccessError::NotMember)
        )
    }

    fn is_access_denied(&self) -> bool {
        matches!(
            self,
            GetWorkspaceKekBackupError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied)
        )
    }
}

/// Get workspace KEK backup handler
pub struct GetWorkspaceKekBackupHandler<BR: ?Sized, MR: ?Sized, RR: ?Sized> {
    backup_repo: Arc<BR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<BR, MR, RR> GetWorkspaceKekBackupHandler<BR, MR, RR>
where
    BR: WorkspaceKekBackupRepository + ?Sized,
    MR: WorkspaceMemberRepository + ?Sized,
    RR: WorkspaceRoleRepository + ?Sized,
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
        // 1. Check membership and Read permission
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            query.workspace_id,
            query.user_id,
            WorkspacePermission::Read,
        )
        .await
        .map_err(GetWorkspaceKekBackupError::WorkspaceAccess)?;

        // 3. Get active backup
        let backup = self
            .backup_repo
            .find_active_by_workspace_and_user(query.workspace_id, query.user_id)
            .await
            .map_err(GetWorkspaceKekBackupError::BackupRepository)?
            .ok_or(GetWorkspaceKekBackupError::BackupNotFound)?;

        Ok(GetWorkspaceKekBackupResult { backup: backup.into() })
    }
}
