//! List workspace invitations query
//!
//! Returns active invitations for a workspace.
//! Requires PoP + member:invite permission.

use crate::dto::WorkspaceInvitationDto;
use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceInvitationRepository, WorkspaceMemberRepository,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository, permission,
};
use std::sync::Arc;
use thiserror::Error;

/// List invitations query
#[derive(Debug)]
pub struct ListInvitationsQuery {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
}

/// Invitation with role name for list response
#[derive(Debug)]
pub struct InvitationWithRoleName {
    pub invitation: WorkspaceInvitationDto,
    pub role_name: Option<String>,
}

/// List invitations result
#[derive(Debug)]
pub struct ListInvitationsResult {
    pub invitations: Vec<InvitationWithRoleName>,
}

/// List invitations error
#[derive(Debug, Error)]
pub enum ListInvitationsError<
    MR: std::error::Error,
    RR: std::error::Error,
    RPR: std::error::Error,
    IR: std::error::Error,
> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("invitation repository error: {0}")]
    InvitationRepository(IR),
}

crate::types::impl_app_error!(
    [MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error, IR: std::error::Error]
    ListInvitationsError<MR, RR, RPR, IR>,
    not_found: [
        ListInvitationsError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        ListInvitationsError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
);

/// List invitations handler
pub struct ListInvitationsHandler<MR: ?Sized, RR: ?Sized, RPR: ?Sized, IR: ?Sized> {
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    invitation_repo: Arc<IR>,
}

impl<MR: ?Sized, RR: ?Sized, RPR: ?Sized, IR: ?Sized>
    ListInvitationsHandler<MR, RR, RPR, IR>
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
        query: ListInvitationsQuery,
    ) -> Result<ListInvitationsResult, ListInvitationsError<MR::Error, RR::Error, RPR::Error, IR::Error>>
    {
        // 1. Permission check (member:invite)
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            query.workspace_id,
            query.user_id,
            permission::MEMBER_INVITE,
        )
        .await
        .map_err(ListInvitationsError::WorkspaceAccess)?;

        // 2. Fetch active invitations
        let invitations = self
            .invitation_repo
            .find_active_by_workspace_id(query.workspace_id)
            .await
            .map_err(ListInvitationsError::InvitationRepository)?;

        // 3. Fetch roles for role_name mapping
        let role_ids: Vec<_> = invitations
            .iter()
            .filter_map(|i| i.role_id)
            .collect();
        let roles = self
            .role_repo
            .find_by_ids(&role_ids)
            .await
            .map_err(|e| ListInvitationsError::WorkspaceAccess(WorkspaceAccessError::RoleRepository(e)))?;
        let role_map: std::collections::HashMap<_, _> = roles
            .into_iter()
            .map(|r| (r.id, r.name))
            .collect();

        Ok(ListInvitationsResult {
            invitations: invitations
                .into_iter()
                .map(|i| {
                    let role_name = i.role_id.and_then(|rid| role_map.get(&rid).cloned());
                    InvitationWithRoleName {
                        invitation: i.into(),
                        role_name,
                    }
                })
                .collect(),
        })
    }
}
