//! Invitation creation service trait
//!
//! Defines the interface for transactional invitation creation.
//! The infrastructure layer provides the implementation that:
//! - Acquires FOR SHARE lock on workspace row
//! - Validates needs_kek_rotation = false
//! - Validates kek_version == MAX(workspace_kek_backups.key_version)
//! - Verifies at least one active workspace encrypted key exists
//! - Inserts the invitation with constraint violation handling

use async_trait::async_trait;
use domain::workspace::WorkspaceInvitation;
use thiserror::Error;

/// Invitation creation errors (transactional)
#[derive(Debug, Error)]
pub enum InvitationCreationError {
    #[error("workspace requires KEK rotation before invitations can be created")]
    NeedsKekRotation,

    #[error("kek_version must equal MAX(workspace_kek_backups.key_version)")]
    KekVersionMismatch,

    #[error("no active KEK found for workspace")]
    NoActiveKek,

    #[error("workspace not found")]
    WorkspaceNotFound,

    #[error("token_hash already exists")]
    TokenHashConflict,

    #[error("invitation_id already exists")]
    InvitationIdConflict,

    #[error("role has been deleted")]
    RoleDeleted,

    #[error("database error: {0}")]
    Database(String),
}

/// Invitation creation service trait
///
/// Creates an invitation atomically in a single transaction:
/// - FOR SHARE lock on workspace row
/// - Check needs_kek_rotation = false
/// - Validate kek_version == MAX(workspace_kek_backups.key_version)
/// - Verify at least one active workspace encrypted key exists
/// - INSERT workspace_invitations with constraint violation handling
#[async_trait]
pub trait InvitationCreationService: Send + Sync {
    async fn create_atomic(
        &self,
        invitation: &WorkspaceInvitation,
    ) -> Result<(), InvitationCreationError>;
}
