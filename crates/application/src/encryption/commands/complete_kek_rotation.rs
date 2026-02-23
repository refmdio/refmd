//! Complete KEK rotation command
//!
//! Clears the needs_kek_rotation flag and updates min_kek_version after
//! the client has distributed new KEKs to all active devices.
//!
//! Delegates to KekRotationCompletionService for atomic check+update
//! with a FOR UPDATE lock on the workspace row.

use domain::identity::UserId;
use domain::workspace::{WorkspaceId, WorkspaceMemberRepository};
use std::sync::Arc;

use crate::encryption::KekRotationCompletionError;
use crate::encryption::KekRotationCompletionService;
use crate::util::workspace_access::{check_workspace_membership, MembershipError};
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
pub enum CompleteKekRotationError<MR: std::error::Error> {
    #[error(transparent)]
    Membership(MembershipError<MR>),

    #[error(transparent)]
    Completion(KekRotationCompletionError),
}

impl<MR: std::error::Error> crate::types::AppError for CompleteKekRotationError<MR> {
    fn is_access_denied(&self) -> bool {
        false
    }

    fn is_invalid_input(&self) -> bool {
        matches!(
            self,
            CompleteKekRotationError::Completion(KekRotationCompletionError::InvalidVersion { .. })
                | CompleteKekRotationError::Completion(
                    KekRotationCompletionError::NotNeedsRotation
                )
                | CompleteKekRotationError::Completion(
                    KekRotationCompletionError::DistributionIncomplete
                )
        )
    }

    fn is_not_found(&self) -> bool {
        matches!(
            self,
            CompleteKekRotationError::Completion(KekRotationCompletionError::WorkspaceNotFound)
                | CompleteKekRotationError::Membership(MembershipError::NotMember)
        )
    }
}

/// Complete KEK rotation handler
pub struct CompleteKekRotationHandler<MR: ?Sized> {
    member_repo: Arc<MR>,
    rotation_service: Arc<dyn KekRotationCompletionService>,
}

impl<MR> CompleteKekRotationHandler<MR>
where
    MR: WorkspaceMemberRepository + ?Sized,
{
    pub fn new(
        member_repo: Arc<MR>,
        rotation_service: Arc<dyn KekRotationCompletionService>,
    ) -> Self {
        Self {
            member_repo,
            rotation_service,
        }
    }

    pub async fn handle(
        &self,
        command: CompleteKekRotationCommand,
    ) -> Result<CompleteKekRotationResult, CompleteKekRotationError<MR::Error>> {
        // 1. Check membership (KEK endpoints require PoP + membership, not RBAC)
        check_workspace_membership(
            &self.member_repo,
            command.workspace_id,
            command.user_id,
        )
        .await
        .map_err(CompleteKekRotationError::Membership)?;

        // 2. Atomic check + update in a single transaction with FOR UPDATE lock
        //    Distribution check is scoped to the requesting user's devices
        //    (each user can only distribute KEK to their own devices via ECDH).
        self.rotation_service
            .complete_atomic(command.workspace_id, command.user_id, command.new_min_kek_version)
            .await
            .map_err(CompleteKekRotationError::Completion)?;

        Ok(CompleteKekRotationResult {
            workspace_id: command.workspace_id,
            new_min_kek_version: command.new_min_kek_version,
        })
    }
}
