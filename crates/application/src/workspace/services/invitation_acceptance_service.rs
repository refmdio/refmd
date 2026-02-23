//! Invitation acceptance service trait
//!
//! Defines the interface for atomic invitation acceptance.
//! The infrastructure layer provides the transactional implementation.

use async_trait::async_trait;
use domain::identity::UserId;
use domain::workspace::{InvitationId, WorkspaceId};
use thiserror::Error;

/// Result of accepting an invitation
#[derive(Debug)]
pub struct InvitationAcceptanceResult {
    pub invitation_id: InvitationId,
    pub workspace_id: WorkspaceId,
    pub workspace_name: String,
    pub role_name: Option<String>,
    pub encrypted_kek: Vec<u8>,
    pub kek_nonce: Vec<u8>,
    pub kek_version: i32,
}

/// Invitation acceptance errors
#[derive(Debug, Error)]
pub enum InvitationAcceptanceError {
    #[error("invitation not found")]
    NotFound,

    #[error("invitation has been revoked")]
    Revoked,

    #[error("invitation has expired")]
    Expired,

    #[error("invitation has already been used")]
    AlreadyUsed,

    #[error("email does not match the invitation")]
    EmailMismatch,

    #[error("role has been deleted")]
    RoleDeleted,

    #[error("KEK version is stale — workspace key has been rotated")]
    StaleKekVersion,

    #[error("KEK rotation is in progress")]
    KekRotationInProgress,

    #[error("deadlock detected — retry")]
    Deadlock,

    #[error("database error: {0}")]
    Database(String),
}

/// Invitation acceptance service trait
///
/// Accepts an invitation atomically in a single transaction:
/// - Loads and validates the invitation
/// - Checks workspace KEK version compatibility and email match
/// - Sets is_used=true (or skips if already a member)
/// - Creates workspace member (or skips if already a member)
#[async_trait]
pub trait InvitationAcceptanceService: Send + Sync {
    async fn accept_atomic(
        &self,
        token_hash: &str,
        user_id: UserId,
        user_email: &str,
    ) -> Result<InvitationAcceptanceResult, InvitationAcceptanceError>;
}
