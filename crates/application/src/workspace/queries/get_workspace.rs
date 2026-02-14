//! Get workspace query
//!
//! Returns workspace details with membership info for the requesting user.

use crate::dto::{WorkspaceDto, WorkspaceMemberDto, WorkspaceRoleDto};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};
use std::sync::Arc;
use thiserror::Error;

/// Get workspace query
#[derive(Debug)]
pub struct GetWorkspaceQuery {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
}

/// Get workspace result
#[derive(Debug)]
pub struct GetWorkspaceResult {
    pub workspace: WorkspaceDto,
    pub membership: WorkspaceMemberDto,
    pub role: WorkspaceRoleDto,
}

/// Get workspace error
#[derive(Debug, Error)]
pub enum GetWorkspaceError<WR: std::error::Error, WMR: std::error::Error, WRR: std::error::Error> {
    #[error("workspace not found")]
    WorkspaceNotFound,

    #[error("not a member of this workspace")]
    NotAMember,

    #[error("role not found")]
    RoleNotFound,

    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),

    #[error("workspace member repository error: {0}")]
    WorkspaceMemberRepository(WMR),

    #[error("workspace role repository error: {0}")]
    WorkspaceRoleRepository(WRR),
}

impl<WR, WMR, WRR> crate::types::AppError for GetWorkspaceError<WR, WMR, WRR>
where
    WR: std::error::Error,
    WMR: std::error::Error,
    WRR: std::error::Error,
{
    fn is_not_found(&self) -> bool {
        matches!(self, GetWorkspaceError::WorkspaceNotFound)
    }

    fn is_access_denied(&self) -> bool {
        matches!(self, GetWorkspaceError::NotAMember)
    }
}

/// Get workspace handler
pub struct GetWorkspaceHandler<WR: ?Sized, WMR: ?Sized, WRR: ?Sized> {
    workspace_repo: Arc<WR>,
    member_repo: Arc<WMR>,
    role_repo: Arc<WRR>,
}

impl<WR: ?Sized, WMR: ?Sized, WRR: ?Sized> GetWorkspaceHandler<WR, WMR, WRR>
where
    WR: WorkspaceRepository,
    WMR: WorkspaceMemberRepository,
    WRR: WorkspaceRoleRepository,
{
    pub fn new(workspace_repo: Arc<WR>, member_repo: Arc<WMR>, role_repo: Arc<WRR>) -> Self {
        Self {
            workspace_repo,
            member_repo,
            role_repo,
        }
    }

    pub async fn handle(
        &self,
        query: GetWorkspaceQuery,
    ) -> Result<GetWorkspaceResult, GetWorkspaceError<WR::Error, WMR::Error, WRR::Error>> {
        // Get workspace
        let workspace = self
            .workspace_repo
            .find_by_id(query.workspace_id)
            .await
            .map_err(GetWorkspaceError::WorkspaceRepository)?
            .ok_or(GetWorkspaceError::WorkspaceNotFound)?;

        // Check membership
        let membership = self
            .member_repo
            .find_by_workspace_and_user(query.workspace_id, query.user_id)
            .await
            .map_err(GetWorkspaceError::WorkspaceMemberRepository)?
            .ok_or(GetWorkspaceError::NotAMember)?;

        // Get role
        let role = self
            .role_repo
            .find_by_id(membership.role_id)
            .await
            .map_err(GetWorkspaceError::WorkspaceRoleRepository)?
            .ok_or(GetWorkspaceError::RoleNotFound)?;

        Ok(GetWorkspaceResult {
            workspace: workspace.into(),
            membership: membership.into(),
            role: role.into(),
        })
    }
}
