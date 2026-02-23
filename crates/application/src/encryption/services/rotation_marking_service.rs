//! Rotation marking service trait
//!
//! Defines the interface for atomically marking a workspace for KEK rotation
//! and revoking its active invitations. The infrastructure layer provides the
//! transactional implementation.

use async_trait::async_trait;
use domain::workspace::WorkspaceId;

/// Rotation marking service trait
///
/// Atomically sets `needs_kek_rotation = true` on a workspace and revokes
/// all active invitations for that workspace in a single transaction.
///
/// Both operations must succeed or both rollback because:
/// - If workspace is marked but invitations remain, stale-KEK invitations
///   can still be accepted (security hole).
/// - If invitations are revoked but workspace is not marked, the rotation
///   signal is lost (correctness bug).
#[async_trait]
pub trait RotationMarkingService: Send + Sync {
    /// Mark the workspace for KEK rotation and revoke all active invitations atomically.
    /// Returns the number of invitations revoked.
    async fn mark_rotation_and_revoke_invitations(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<i64, RotationMarkingError>;
}

/// Error during atomic rotation marking
#[derive(Debug, thiserror::Error)]
pub enum RotationMarkingError {
    #[error("workspace not found")]
    WorkspaceNotFound,

    #[error("database error: {0}")]
    Database(String),
}
