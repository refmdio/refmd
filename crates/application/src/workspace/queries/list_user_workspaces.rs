//! List user workspaces query
//!
//! Returns all workspaces a user is a member of.

use domain::identity::UserId;
use domain::workspace::{
    RoleId, Workspace, WorkspaceId, WorkspaceMember, WorkspaceMemberRepository,
    WorkspaceRepository, WorkspaceRole, WorkspaceRoleRepository,
};
use std::sync::Arc;
use thiserror::Error;

/// List user workspaces query
#[derive(Debug)]
pub struct ListUserWorkspacesQuery {
    pub user_id: UserId,
}

/// Workspace with membership info
#[derive(Debug)]
pub struct WorkspaceWithMembership {
    pub workspace: Workspace,
    pub membership: WorkspaceMember,
    pub role: WorkspaceRole,
}

/// List user workspaces result
#[derive(Debug)]
pub struct ListUserWorkspacesResult {
    pub workspaces: Vec<WorkspaceWithMembership>,
}

/// List user workspaces error
#[derive(Debug, Error)]
pub enum ListUserWorkspacesError<
    WR: std::error::Error,
    WMR: std::error::Error,
    WRR: std::error::Error,
> {
    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),

    #[error("workspace member repository error: {0}")]
    WorkspaceMemberRepository(WMR),

    #[error("workspace role repository error: {0}")]
    WorkspaceRoleRepository(WRR),

    #[error("data inconsistency: workspace {0} not found but membership exists")]
    WorkspaceNotFound(WorkspaceId),

    #[error("data inconsistency: role {0} not found but membership references it")]
    RoleNotFound(RoleId),
}

/// List user workspaces handler
pub struct ListUserWorkspacesHandler<WR, WMR, WRR> {
    workspace_repo: Arc<WR>,
    member_repo: Arc<WMR>,
    role_repo: Arc<WRR>,
}

impl<WR, WMR, WRR> ListUserWorkspacesHandler<WR, WMR, WRR>
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
        query: ListUserWorkspacesQuery,
    ) -> Result<ListUserWorkspacesResult, ListUserWorkspacesError<WR::Error, WMR::Error, WRR::Error>>
    {
        // Get all memberships for the user
        let memberships = self
            .member_repo
            .find_by_user_id(query.user_id)
            .await
            .map_err(ListUserWorkspacesError::WorkspaceMemberRepository)?;

        let mut workspaces = Vec::with_capacity(memberships.len());

        for membership in memberships {
            // Get workspace
            let workspace = self
                .workspace_repo
                .find_by_id(membership.workspace_id)
                .await
                .map_err(ListUserWorkspacesError::WorkspaceRepository)?
                .ok_or_else(|| {
                    tracing::error!(
                        workspace_id = %membership.workspace_id,
                        user_id = %membership.user_id,
                        "Data inconsistency: workspace not found but membership exists"
                    );
                    ListUserWorkspacesError::WorkspaceNotFound(membership.workspace_id)
                })?;

            // Get role
            let role = self
                .role_repo
                .find_by_id(membership.role_id)
                .await
                .map_err(ListUserWorkspacesError::WorkspaceRoleRepository)?
                .ok_or_else(|| {
                    tracing::error!(
                        role_id = %membership.role_id,
                        workspace_id = %membership.workspace_id,
                        user_id = %membership.user_id,
                        "Data inconsistency: role not found but membership references it"
                    );
                    ListUserWorkspacesError::RoleNotFound(membership.role_id)
                })?;

            workspaces.push(WorkspaceWithMembership {
                workspace,
                membership,
                role,
            });
        }

        // Sort: default workspace first, then by name
        workspaces.sort_by(
            |a, b| match (a.membership.is_default, b.membership.is_default) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.workspace.name.cmp(&b.workspace.name),
            },
        );

        Ok(ListUserWorkspacesResult { workspaces })
    }
}
