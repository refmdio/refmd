//! Get workspace key query
//!
//! Retrieves the active KEK for a user's device in a workspace.
//! Requires workspace membership (Read permission minimum).

use domain::encryption::{DeviceId, WorkspaceEncryptedKey, WorkspaceEncryptedKeyRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
    can_perform,
};
use std::sync::Arc;
use thiserror::Error;

/// Get workspace key query
#[derive(Debug)]
pub struct GetWorkspaceKeyQuery {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub device_id: Option<DeviceId>,
}

/// Get workspace key result
#[derive(Debug)]
pub struct GetWorkspaceKeyResult {
    pub key: WorkspaceEncryptedKey,
}

/// Get workspace key error
#[derive(Debug, Error)]
pub enum GetWorkspaceKeyError<WKR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
{
    #[error("workspace key not found")]
    KeyNotFound,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot access this workspace")]
    PermissionDenied,

    #[error("workspace key repository error: {0}")]
    WorkspaceKeyRepository(WKR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<WKR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    GetWorkspaceKeyError<WKR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, GetWorkspaceKeyError::KeyNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            GetWorkspaceKeyError::NotMember | GetWorkspaceKeyError::PermissionDenied
        )
    }
}

/// Get workspace key handler
pub struct GetWorkspaceKeyHandler<WKR, MR, RR> {
    workspace_key_repo: Arc<WKR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<WKR, MR, RR> GetWorkspaceKeyHandler<WKR, MR, RR>
where
    WKR: WorkspaceEncryptedKeyRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
{
    pub fn new(workspace_key_repo: Arc<WKR>, member_repo: Arc<MR>, role_repo: Arc<RR>) -> Self {
        Self {
            workspace_key_repo,
            member_repo,
            role_repo,
        }
    }

    pub async fn handle(
        &self,
        query: GetWorkspaceKeyQuery,
    ) -> Result<GetWorkspaceKeyResult, GetWorkspaceKeyError<WKR::Error, MR::Error, RR::Error>> {
        // 1. Check membership
        let member = self
            .member_repo
            .find_by_workspace_and_user(query.workspace_id, query.user_id)
            .await
            .map_err(GetWorkspaceKeyError::MemberRepository)?
            .ok_or(GetWorkspaceKeyError::NotMember)?;

        // 2. Get role and check Read permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(GetWorkspaceKeyError::RoleRepository)?
            .ok_or(GetWorkspaceKeyError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Read) {
            return Err(GetWorkspaceKeyError::PermissionDenied);
        }

        // 3. Get active key
        let key = if let Some(device_id) = query.device_id {
            self.workspace_key_repo
                .find_active_by_device(query.workspace_id, query.user_id, device_id)
                .await
                .map_err(GetWorkspaceKeyError::WorkspaceKeyRepository)?
        } else {
            self.workspace_key_repo
                .find_active_by_user(query.workspace_id, query.user_id)
                .await
                .map_err(GetWorkspaceKeyError::WorkspaceKeyRepository)?
        };

        let key = key.ok_or(GetWorkspaceKeyError::KeyNotFound)?;

        Ok(GetWorkspaceKeyResult { key })
    }
}
