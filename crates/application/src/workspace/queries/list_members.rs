//! List workspace members query
//!
//! Returns all members of a workspace with their role info.
//! Requires member:list permission.

use crate::dto::{WorkspaceMemberDto, WorkspaceRoleDto};
use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use domain::identity::{UserId, UserRepository};
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspaceRolePermissionRepository,
    WorkspaceRoleRepository, permission,
};
use std::sync::Arc;
use thiserror::Error;

/// List members query
#[derive(Debug)]
pub struct ListMembersQuery {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
}

/// Member with role and user info
#[derive(Debug)]
pub struct MemberWithRoleDto {
    pub member: WorkspaceMemberDto,
    pub role: WorkspaceRoleDto,
    pub user_name: String,
    pub user_email: String,
}

/// List members result
#[derive(Debug)]
pub struct ListMembersResult {
    pub members: Vec<MemberWithRoleDto>,
}

/// List members error
#[derive(Debug, Error)]
pub enum ListMembersError<MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error, UR: std::error::Error> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),

    #[error("role permission repository error: {0}")]
    RolePermissionRepository(RPR),

    #[error("user repository error: {0}")]
    UserRepository(UR),

    #[error("data integrity error: member references non-existent role {role_id}")]
    RoleMismatch { role_id: String },

    #[error("data integrity error: member references non-existent user {user_id}")]
    UserMissing { user_id: String },
}

crate::types::impl_app_error!(
    [MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error, UR: std::error::Error]
    ListMembersError<MR, RR, RPR, UR>,
    not_found: [
        ListMembersError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        ListMembersError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
);

/// List members handler
pub struct ListMembersHandler<MR: ?Sized, RR: ?Sized, RPR: ?Sized, UR: ?Sized> {
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    user_repo: Arc<UR>,
}

impl<MR: ?Sized, RR: ?Sized, RPR: ?Sized, UR: ?Sized> ListMembersHandler<MR, RR, RPR, UR>
where
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
    UR: UserRepository,
{
    pub fn new(member_repo: Arc<MR>, role_repo: Arc<RR>, role_perm_repo: Arc<RPR>, user_repo: Arc<UR>) -> Self {
        Self {
            member_repo,
            role_repo,
            role_perm_repo,
            user_repo,
        }
    }

    pub async fn handle(
        &self,
        query: ListMembersQuery,
    ) -> Result<ListMembersResult, ListMembersError<MR::Error, RR::Error, RPR::Error, UR::Error>> {
        // 1. Check permission
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            query.workspace_id,
            query.user_id,
            permission::MEMBER_LIST,
        )
        .await
        .map_err(ListMembersError::WorkspaceAccess)?;

        // 2. Fetch all members
        let members = self
            .member_repo
            .find_by_workspace_id(query.workspace_id)
            .await
            .map_err(ListMembersError::MemberRepository)?;

        // 3. Batch-fetch roles
        let role_ids: Vec<_> = members.iter().map(|m| m.role_id).collect();
        let roles = self
            .role_repo
            .find_by_ids(&role_ids)
            .await
            .map_err(ListMembersError::RoleRepository)?;

        let role_map: std::collections::HashMap<_, _> =
            roles.into_iter().map(|r| (r.id, r)).collect();

        // 3b. Batch-fetch permission overrides for all roles
        let all_overrides = self
            .role_perm_repo
            .find_by_role_ids(&role_ids)
            .await
            .map_err(ListMembersError::RolePermissionRepository)?;

        let mut overrides_by_role: std::collections::HashMap<domain::workspace::RoleId, Vec<(String, bool)>> =
            std::collections::HashMap::new();
        for o in all_overrides {
            overrides_by_role
                .entry(o.role_id)
                .or_default()
                .push((o.permission, o.granted));
        }

        // 4. Batch-fetch users
        let user_ids: Vec<_> = members.iter().map(|m| m.user_id).collect();
        let users = self
            .user_repo
            .find_by_ids(&user_ids)
            .await
            .map_err(ListMembersError::UserRepository)?;

        let user_map: std::collections::HashMap<_, _> =
            users.into_iter().map(|u| (u.id, u)).collect();

        // 5. Build result — fail if any member references a non-existent role or user
        let members = members
            .into_iter()
            .map(|m| {
                let role = role_map
                    .get(&m.role_id)
                    .cloned()
                    .ok_or_else(|| ListMembersError::RoleMismatch {
                        role_id: m.role_id.to_string(),
                    })?;
                let user = user_map
                    .get(&m.user_id)
                    .ok_or_else(|| ListMembersError::UserMissing {
                        user_id: m.user_id.to_string(),
                    })?;
                let overrides = overrides_by_role.get(&m.role_id).cloned().unwrap_or_default();
                let mut role_dto: WorkspaceRoleDto = role.into();
                role_dto.permission_overrides = overrides;
                Ok(MemberWithRoleDto {
                    member: m.into(),
                    role: role_dto,
                    user_name: user.name.clone(),
                    user_email: user.email.as_str().to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ListMembersResult { members })
    }
}
