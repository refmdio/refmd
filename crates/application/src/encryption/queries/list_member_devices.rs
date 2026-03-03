//! List workspace member's active devices
//!
//! Returns active (non-revoked) devices with public keys for a specified workspace member.
//! Requires caller to be a workspace member with member:list permission.

use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use chrono::{DateTime, Utc};
use domain::encryption::{DeviceId, DeviceRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspaceRolePermissionRepository,
    WorkspaceRoleRepository, permission,
};
use std::sync::Arc;
use thiserror::Error;

/// List member devices query
#[derive(Debug)]
pub struct ListMemberDevicesQuery {
    pub workspace_id: WorkspaceId,
    pub caller_user_id: UserId,
    pub target_user_id: UserId,
}

/// Member device DTO (minimal public key info)
#[derive(Debug, Clone)]
pub struct MemberDeviceDto {
    pub device_id: DeviceId,
    pub signing_public_key: Vec<u8>,
    pub ecdh_public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// List member devices result
#[derive(Debug)]
pub struct ListMemberDevicesResult {
    pub devices: Vec<MemberDeviceDto>,
}

/// List member devices error
#[derive(Debug, Error)]
pub enum ListMemberDevicesError<
    MR: std::error::Error,
    RR: std::error::Error,
    RPR: std::error::Error,
    DR: std::error::Error,
> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("target user is not a member of this workspace")]
    TargetNotMember,

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("device repository error: {0}")]
    DeviceRepository(DR),
}

crate::types::impl_app_error!(
    [MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error, DR: std::error::Error]
    ListMemberDevicesError<MR, RR, RPR, DR>,
    not_found: [
        ListMemberDevicesError::WorkspaceAccess(WorkspaceAccessError::NotMember),
        ListMemberDevicesError::TargetNotMember,
    ],
    access_denied: [
        ListMemberDevicesError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
);

/// List member devices handler
pub struct ListMemberDevicesHandler<MR: ?Sized, RR: ?Sized, RPR: ?Sized, DR: ?Sized> {
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    device_repo: Arc<DR>,
}

impl<MR: ?Sized, RR: ?Sized, RPR: ?Sized, DR: ?Sized>
    ListMemberDevicesHandler<MR, RR, RPR, DR>
where
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
    DR: DeviceRepository,
{
    pub fn new(
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
        device_repo: Arc<DR>,
    ) -> Self {
        Self {
            member_repo,
            role_repo,
            role_perm_repo,
            device_repo,
        }
    }

    pub async fn handle(
        &self,
        query: ListMemberDevicesQuery,
    ) -> Result<
        ListMemberDevicesResult,
        ListMemberDevicesError<MR::Error, RR::Error, RPR::Error, DR::Error>,
    > {
        // 1. Check caller has member:list permission
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            query.workspace_id,
            query.caller_user_id,
            permission::MEMBER_LIST,
        )
        .await
        .map_err(ListMemberDevicesError::WorkspaceAccess)?;

        // 2. Verify target user is a workspace member
        self.member_repo
            .find_by_workspace_and_user(query.workspace_id, query.target_user_id)
            .await
            .map_err(ListMemberDevicesError::MemberRepository)?
            .ok_or(ListMemberDevicesError::TargetNotMember)?;

        // 3. Fetch active devices for target user
        let devices = self
            .device_repo
            .find_active_by_user_id(query.target_user_id)
            .await
            .map_err(ListMemberDevicesError::DeviceRepository)?;

        let devices = devices
            .into_iter()
            .map(|d| MemberDeviceDto {
                device_id: d.id,
                signing_public_key: d.signing_public_key,
                ecdh_public_key: d.ecdh_public_key,
                created_at: d.created_at,
            })
            .collect();

        Ok(ListMemberDevicesResult { devices })
    }
}
