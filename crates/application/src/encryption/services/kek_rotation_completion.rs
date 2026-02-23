//! KEK rotation completion service trait
//!
//! Defines the interface for transactional KEK rotation completion.
//! The infrastructure layer provides the implementation that:
//! - Acquires FOR UPDATE lock on workspace row
//! - Validates needs_kek_rotation and version in-transaction
//! - Checks the requesting user's active devices have received the new KEK
//! - Updates workspace min_kek_version and clears rotation flag
//!
//! Device distribution check is scoped to the requesting user because
//! E2EE key distribution is user-scoped: User A can only encrypt KEK
//! for User A's devices (using A's ECDH private key). Other members
//! obtain the new KEK via UMK backup restore on their next access.

use async_trait::async_trait;
use domain::identity::UserId;
use domain::workspace::WorkspaceId;
use thiserror::Error;

/// KEK rotation completion errors (transactional)
#[derive(Debug, Error)]
pub enum KekRotationCompletionError {
    #[error("workspace not found")]
    WorkspaceNotFound,

    #[error("workspace does not need KEK rotation")]
    NotNeedsRotation,

    #[error("invalid version: new {new} must be greater than current {current}")]
    InvalidVersion { current: i32, new: i32 },

    #[error("not all active devices have received the new KEK version")]
    DistributionIncomplete,

    #[error("database error: {0}")]
    Database(String),
}

/// KEK rotation completion service trait
///
/// Completes KEK rotation atomically in a single transaction:
/// - FOR UPDATE lock on workspace row
/// - Check needs_kek_rotation = true
/// - Validate new_min_kek_version > current min_kek_version
/// - Verify the requesting user's active devices have a key >= new version
/// - Verify no active key on the user's active devices has version < new version
/// - UPDATE workspace min_kek_version and clear needs_kek_rotation flag
#[async_trait]
pub trait KekRotationCompletionService: Send + Sync {
    async fn complete_atomic(
        &self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        new_min_kek_version: i32,
    ) -> Result<(), KekRotationCompletionError>;
}
