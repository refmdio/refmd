//! List workspace roles query
//!
//! Returns all roles in a workspace with their permission overrides.
//! Requires membership only (no specific permission).

use crate::dto::WorkspaceRoleDto;
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspaceRolePermissionRepository,
    WorkspaceRoleRepository,
};
use std::sync::Arc;
use thiserror::Error;

/// List roles query
#[derive(Debug)]
pub struct ListRolesQuery {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
}

/// List roles result
#[derive(Debug)]
pub struct ListRolesResult {
    pub roles: Vec<WorkspaceRoleDto>,
}

/// List roles error
#[derive(Debug, Error)]
pub enum ListRolesError<MR: std::error::Error, RR: std::error::Error, PR: std::error::Error> {
    #[error("not a member of this workspace")]
    NotMember,

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),

    #[error("role permission repository error: {0}")]
    RolePermissionRepository(PR),
}

impl<MR: std::error::Error, RR: std::error::Error, PR: std::error::Error> crate::types::AppError
    for ListRolesError<MR, RR, PR>
{
    fn is_not_found(&self) -> bool {
        matches!(self, Self::NotMember)
    }
}

/// List roles handler
pub struct ListRolesHandler<MR: ?Sized, RR: ?Sized, PR: ?Sized> {
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<PR>,
}

impl<MR: ?Sized, RR: ?Sized, PR: ?Sized> ListRolesHandler<MR, RR, PR>
where
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    PR: WorkspaceRolePermissionRepository,
{
    pub fn new(member_repo: Arc<MR>, role_repo: Arc<RR>, role_perm_repo: Arc<PR>) -> Self {
        Self {
            member_repo,
            role_repo,
            role_perm_repo,
        }
    }

    pub async fn handle(
        &self,
        query: ListRolesQuery,
    ) -> Result<ListRolesResult, ListRolesError<MR::Error, RR::Error, PR::Error>> {
        // 1. Check membership
        self.member_repo
            .find_by_workspace_and_user(query.workspace_id, query.user_id)
            .await
            .map_err(ListRolesError::MemberRepository)?
            .ok_or(ListRolesError::NotMember)?;

        // 2. Fetch all roles for this workspace
        let roles = self
            .role_repo
            .find_by_workspace_id(query.workspace_id)
            .await
            .map_err(ListRolesError::RoleRepository)?;

        // 3. Fetch permission overrides for all roles in one batch
        let role_ids: Vec<_> = roles.iter().map(|r| r.id).collect();
        let all_overrides = self
            .role_perm_repo
            .find_by_role_ids(&role_ids)
            .await
            .map_err(ListRolesError::RolePermissionRepository)?;

        // 4. Group overrides by role_id (O(N) instead of O(R*P))
        let mut overrides_by_role: std::collections::HashMap<domain::workspace::RoleId, Vec<(String, bool)>> =
            std::collections::HashMap::new();
        for o in all_overrides {
            overrides_by_role
                .entry(o.role_id)
                .or_default()
                .push((o.permission, o.granted));
        }

        // 5. Attach overrides to each role DTO
        let roles: Vec<WorkspaceRoleDto> = roles
            .into_iter()
            .map(|r| {
                let overrides = overrides_by_role.remove(&r.id).unwrap_or_default();
                let mut dto: WorkspaceRoleDto = r.into();
                dto.permission_overrides = overrides;
                dto
            })
            .collect();

        Ok(ListRolesResult { roles })
    }
}
