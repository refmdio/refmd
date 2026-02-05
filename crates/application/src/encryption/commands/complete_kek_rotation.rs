//! Complete KEK rotation command
//!
//! Clears the needs_kek_rotation flag and updates min_kek_version after
//! the client has distributed new KEKs to all active devices.

use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRepository,
    WorkspaceRoleRepository, can_perform,
};
use std::sync::Arc;
use thiserror::Error;

/// Complete KEK rotation command
#[derive(Debug)]
pub struct CompleteKekRotationCommand {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    /// New minimum KEK version (must be greater than current)
    pub new_min_kek_version: i32,
}

/// Complete KEK rotation result
#[derive(Debug)]
pub struct CompleteKekRotationResult {
    pub workspace_id: WorkspaceId,
    pub new_min_kek_version: i32,
}

/// Complete KEK rotation error
#[derive(Debug, Error)]
pub enum CompleteKekRotationError<WR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
{
    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot manage workspace keys")]
    PermissionDenied,

    #[error("workspace not found")]
    WorkspaceNotFound,

    #[error("invalid version: new version {new} must be greater than current {current}")]
    InvalidVersion { current: i32, new: i32 },

    #[error("workspace does not need KEK rotation")]
    NotNeedsRotation,

    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<WR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    CompleteKekRotationError<WR, MR, RR>
{
    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            CompleteKekRotationError::NotMember | CompleteKekRotationError::PermissionDenied
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            CompleteKekRotationError::InvalidVersion { .. }
                | CompleteKekRotationError::NotNeedsRotation
        )
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, CompleteKekRotationError::WorkspaceNotFound)
    }
}

/// Complete KEK rotation handler
pub struct CompleteKekRotationHandler<WR, MR, RR> {
    workspace_repo: Arc<WR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<WR, MR, RR> CompleteKekRotationHandler<WR, MR, RR>
where
    WR: WorkspaceRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
{
    pub fn new(workspace_repo: Arc<WR>, member_repo: Arc<MR>, role_repo: Arc<RR>) -> Self {
        Self {
            workspace_repo,
            member_repo,
            role_repo,
        }
    }

    pub async fn handle(
        &self,
        command: CompleteKekRotationCommand,
    ) -> Result<CompleteKekRotationResult, CompleteKekRotationError<WR::Error, MR::Error, RR::Error>>
    {
        // 1. Get workspace
        let mut workspace = self
            .workspace_repo
            .find_by_id(command.workspace_id)
            .await
            .map_err(CompleteKekRotationError::WorkspaceRepository)?
            .ok_or(CompleteKekRotationError::WorkspaceNotFound)?;

        // 2. Check membership
        let member = self
            .member_repo
            .find_by_workspace_and_user(command.workspace_id, command.user_id)
            .await
            .map_err(CompleteKekRotationError::MemberRepository)?
            .ok_or(CompleteKekRotationError::NotMember)?;

        // 3. Get role and check Write permission (required for key management)
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(CompleteKekRotationError::RoleRepository)?
            .ok_or(CompleteKekRotationError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Write) {
            return Err(CompleteKekRotationError::PermissionDenied);
        }

        // 4. Check if workspace needs rotation
        if !workspace.needs_kek_rotation {
            return Err(CompleteKekRotationError::NotNeedsRotation);
        }

        // 5. Validate new version is greater than current
        if command.new_min_kek_version <= workspace.min_kek_version {
            return Err(CompleteKekRotationError::InvalidVersion {
                current: workspace.min_kek_version,
                new: command.new_min_kek_version,
            });
        }

        // 6. Update workspace
        workspace.set_min_kek_version(command.new_min_kek_version);
        workspace.clear_kek_rotation_flag();

        // 7. Save workspace
        self.workspace_repo
            .save(&workspace)
            .await
            .map_err(CompleteKekRotationError::WorkspaceRepository)?;

        Ok(CompleteKekRotationResult {
            workspace_id: command.workspace_id,
            new_min_kek_version: command.new_min_kek_version,
        })
    }
}
