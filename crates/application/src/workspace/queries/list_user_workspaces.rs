//! List user workspaces query
//!
//! Returns all workspaces a user is a member of.

use crate::dto::{WorkspaceDto, WorkspaceMemberDto, WorkspaceRoleDto};
use domain::identity::UserId;
use domain::workspace::{
    RoleId, Workspace, WorkspaceId, WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRole,
    WorkspaceRoleRepository,
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
    pub workspace: WorkspaceDto,
    pub membership: WorkspaceMemberDto,
    pub role: WorkspaceRoleDto,
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
pub struct ListUserWorkspacesHandler<WR: ?Sized, WMR: ?Sized, WRR: ?Sized> {
    workspace_repo: Arc<WR>,
    member_repo: Arc<WMR>,
    role_repo: Arc<WRR>,
}

impl<WR: ?Sized, WMR: ?Sized, WRR: ?Sized> ListUserWorkspacesHandler<WR, WMR, WRR>
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

        if memberships.is_empty() {
            return Ok(ListUserWorkspacesResult {
                workspaces: Vec::new(),
            });
        }

        // Batch fetch workspaces and roles (3 queries instead of N+1)
        let workspace_ids: Vec<_> = memberships.iter().map(|m| m.workspace_id).collect();
        let role_ids: Vec<_> = memberships.iter().map(|m| m.role_id).collect();

        let workspaces_list = self
            .workspace_repo
            .find_by_ids(&workspace_ids)
            .await
            .map_err(ListUserWorkspacesError::WorkspaceRepository)?;
        let roles_list = self
            .role_repo
            .find_by_ids(&role_ids)
            .await
            .map_err(ListUserWorkspacesError::WorkspaceRoleRepository)?;

        // Index by ID for O(1) lookup
        let workspace_map: std::collections::HashMap<WorkspaceId, Workspace> =
            workspaces_list.into_iter().map(|w| (w.id, w)).collect();
        let role_map: std::collections::HashMap<RoleId, WorkspaceRole> =
            roles_list.into_iter().map(|r| (r.id, r)).collect();

        let mut workspaces = Vec::with_capacity(memberships.len());

        for membership in memberships {
            let workspace = workspace_map
                .get(&membership.workspace_id)
                .cloned()
                .ok_or_else(|| {
                    tracing::error!(
                        workspace_id = %membership.workspace_id,
                        user_id = %membership.user_id,
                        "Data inconsistency: workspace not found but membership exists"
                    );
                    ListUserWorkspacesError::WorkspaceNotFound(membership.workspace_id)
                })?;

            let role = role_map
                .get(&membership.role_id)
                .cloned()
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
                workspace: workspace.into(),
                membership: membership.into(),
                role: role.into(),
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
