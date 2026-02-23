//! Get workspace KEK backup query
//!
//! Retrieves the active KEK backup for a user in a workspace.
//! Requires workspace membership (Read permission minimum).

use crate::dto::WorkspaceKekBackupDto;
use domain::encryption::WorkspaceKekBackupRepository;
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository,
};
use std::sync::Arc;

use crate::util::workspace_access::{check_workspace_membership, MembershipError};
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
pub enum GetWorkspaceKekBackupError<BR: std::error::Error, MR: std::error::Error> {
    #[error("KEK backup not found")]
    BackupNotFound,

    #[error(transparent)]
    Membership(MembershipError<MR>),

    #[error("backup repository error: {0}")]
    BackupRepository(BR),
}

impl<BR: std::error::Error, MR: std::error::Error>
    crate::types::AppError for GetWorkspaceKekBackupError<BR, MR>
{
    fn is_not_found(&self) -> bool {
        matches!(
            self,
            GetWorkspaceKekBackupError::BackupNotFound
                | GetWorkspaceKekBackupError::Membership(MembershipError::NotMember)
        )
    }
}

/// Get workspace KEK backup handler
pub struct GetWorkspaceKekBackupHandler<BR: ?Sized, MR: ?Sized> {
    backup_repo: Arc<BR>,
    member_repo: Arc<MR>,
}

impl<BR, MR> GetWorkspaceKekBackupHandler<BR, MR>
where
    BR: WorkspaceKekBackupRepository + ?Sized,
    MR: WorkspaceMemberRepository + ?Sized,
{
    pub fn new(backup_repo: Arc<BR>, member_repo: Arc<MR>) -> Self {
        Self {
            backup_repo,
            member_repo,
        }
    }

    pub async fn handle(
        &self,
        query: GetWorkspaceKekBackupQuery,
    ) -> Result<
        GetWorkspaceKekBackupResult,
        GetWorkspaceKekBackupError<BR::Error, MR::Error>,
    > {
        // 1. Check membership (KEK endpoints require PoP + membership, not RBAC)
        check_workspace_membership(
            &self.member_repo,
            query.workspace_id,
            query.user_id,
        )
        .await
        .map_err(GetWorkspaceKekBackupError::Membership)?;

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
