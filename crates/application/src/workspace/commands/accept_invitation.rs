//! Accept invitation command
//!
//! Accepts a workspace invitation using the token hash.
//! Requires PoP authentication but no workspace membership.
//! Delegates to InvitationAcceptanceService for atomic transaction.

use crate::workspace::InvitationAcceptanceService;
use crate::workspace_events::WorkspaceEventPublisher;
use domain::identity::{UserId, UserRepository};
use domain::workspace::{WorkspaceId, WorkspaceMemberRepository};
use std::sync::Arc;
use thiserror::Error;

/// Accept invitation command
#[derive(Debug)]
pub struct AcceptInvitationCommand {
    /// Raw base64url-encoded token (32 bytes when decoded)
    pub token: String,
    pub user_id: UserId,
}

/// Accept invitation result
#[derive(Debug)]
pub struct AcceptInvitationResult {
    pub workspace_id: WorkspaceId,
    pub workspace_name: String,
    pub role_name: Option<String>,
    pub invitation_id: domain::workspace::InvitationId,
    pub accepted_by_email: String,
    pub encrypted_kek: Vec<u8>,
    pub kek_nonce: Vec<u8>,
    pub kek_version: i32,
}

/// Accept invitation error
#[derive(Debug, Error)]
pub enum AcceptInvitationError {
    #[error("invalid token format")]
    InvalidTokenFormat,

    #[error("invalid token length")]
    InvalidTokenLength,

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

    #[error("the role for this invitation has been deleted")]
    RoleDeleted,

    #[error("workspace key has been rotated — this invitation is no longer valid")]
    StaleKekVersion,

    #[error("KEK rotation is in progress")]
    KekRotationInProgress,

    #[error("deadlock detected — please retry")]
    Deadlock,

    #[error("user not found")]
    UserNotFound,

    #[error("user repository error: {0}")]
    UserRepository(String),

    #[error("service error: {0}")]
    Service(String),
}

crate::types::impl_app_error!(
    AcceptInvitationError,
    not_found: [
        AcceptInvitationError::NotFound,
        AcceptInvitationError::UserNotFound,
    ],
    access_denied: [
        AcceptInvitationError::EmailMismatch,
    ],
    invalid_input: [
        AcceptInvitationError::InvalidTokenFormat,
        AcceptInvitationError::InvalidTokenLength,
    ],
    conflict: [
        AcceptInvitationError::KekRotationInProgress,
        AcceptInvitationError::Deadlock,
    ],
    gone: [
        AcceptInvitationError::Revoked,
        AcceptInvitationError::Expired,
        AcceptInvitationError::AlreadyUsed,
        AcceptInvitationError::RoleDeleted,
        AcceptInvitationError::StaleKekVersion,
    ],
);

/// Accept invitation handler
pub struct AcceptInvitationHandler<UR: ?Sized, MR: ?Sized = dyn WorkspaceMemberRepository<Error = crate::types::BoxedError>> {
    user_repo: Arc<UR>,
    workspace_member_repo: Arc<MR>,
    acceptance_service: Arc<dyn InvitationAcceptanceService>,
    workspace_event_publisher: Arc<dyn WorkspaceEventPublisher>,
}

impl<UR: ?Sized, MR: ?Sized> AcceptInvitationHandler<UR, MR>
where
    UR: UserRepository,
    MR: WorkspaceMemberRepository,
{
    pub fn new(
        user_repo: Arc<UR>,
        workspace_member_repo: Arc<MR>,
        acceptance_service: Arc<dyn InvitationAcceptanceService>,
        workspace_event_publisher: Arc<dyn WorkspaceEventPublisher>,
    ) -> Self {
        Self {
            user_repo,
            workspace_member_repo,
            acceptance_service,
            workspace_event_publisher,
        }
    }

    pub async fn handle(
        &self,
        command: AcceptInvitationCommand,
    ) -> Result<AcceptInvitationResult, AcceptInvitationError> {
        use crate::workspace::InvitationAcceptanceError;
        use sha2::{Digest, Sha256};

        // 1. Look up user email for email-bound invitation matching
        let user = self
            .user_repo
            .find_by_id(command.user_id)
            .await
            .map_err(|e| AcceptInvitationError::UserRepository(e.to_string()))?
            .ok_or(AcceptInvitationError::UserNotFound)?;
        let user_email = user.email.to_string();

        // 2. Decode base64url token
        let token_bytes = base64_url::decode(&command.token)
            .map_err(|_| AcceptInvitationError::InvalidTokenFormat)?;

        // 3. Validate token length (must be exactly 32 bytes)
        if token_bytes.len() != 32 {
            return Err(AcceptInvitationError::InvalidTokenLength);
        }

        // 4. Compute token_hash = base64url(SHA-256(token_bytes))
        let hash = Sha256::digest(&token_bytes);
        let token_hash = base64_url::encode(&hash);

        // 5. Delegate to acceptance service (with deadlock auto-retry + exponential backoff)
        const MAX_DEADLOCK_RETRIES: u32 = 3;
        let mut retries = 0;
        let result = loop {
            match self
                .acceptance_service
                .accept_atomic(&token_hash, command.user_id, &user_email)
                .await
            {
                Ok(r) => break Ok(r),
                Err(InvitationAcceptanceError::Deadlock) => {
                    retries += 1;
                    if retries < MAX_DEADLOCK_RETRIES {
                        let backoff_ms = 10 * (1u64 << retries); // 20ms, 40ms
                        tracing::warn!(
                            retries,
                            backoff_ms,
                            "deadlock detected during invitation acceptance, retrying"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                        continue;
                    }
                    break Err(AcceptInvitationError::Deadlock);
                }
                Err(e) => {
                    break Err(match e {
                        InvitationAcceptanceError::NotFound => AcceptInvitationError::NotFound,
                        InvitationAcceptanceError::Revoked => AcceptInvitationError::Revoked,
                        InvitationAcceptanceError::Expired => AcceptInvitationError::Expired,
                        InvitationAcceptanceError::AlreadyUsed => {
                            AcceptInvitationError::AlreadyUsed
                        }
                        InvitationAcceptanceError::EmailMismatch => {
                            AcceptInvitationError::EmailMismatch
                        }
                        InvitationAcceptanceError::RoleDeleted => {
                            AcceptInvitationError::RoleDeleted
                        }
                        InvitationAcceptanceError::StaleKekVersion => {
                            AcceptInvitationError::StaleKekVersion
                        }
                        InvitationAcceptanceError::KekRotationInProgress => {
                            AcceptInvitationError::KekRotationInProgress
                        }
                        InvitationAcceptanceError::Deadlock => unreachable!(),
                        InvitationAcceptanceError::Database(msg) => {
                            AcceptInvitationError::Service(msg)
                        }
                    });
                }
            }
        }?;

        // Best-effort: publish workspace event for real-time notification
        let workspace_id = result.workspace_id;
        let invitation_id = result.invitation_id;
        match self
            .workspace_member_repo
            .find_by_workspace_id(workspace_id)
            .await
        {
            Ok(members) => {
                let member_user_ids: Vec<UserId> = members.iter().map(|m| m.user_id).collect();
                self.workspace_event_publisher
                    .publish(domain::WorkspaceEvent::InvitationAccepted {
                        workspace_id,
                        invitation_id,
                        accepted_by_email: user_email.clone(),
                        member_user_ids,
                    })
                    .await;
            }
            Err(e) => {
                tracing::warn!(
                    %workspace_id,
                    error = %e,
                    "failed to fetch members for SSE broadcast after invitation acceptance"
                );
            }
        }

        Ok(AcceptInvitationResult {
            workspace_id,
            workspace_name: result.workspace_name,
            role_name: result.role_name,
            invitation_id,
            accepted_by_email: user_email,
            encrypted_kek: result.encrypted_kek,
            kek_nonce: result.kek_nonce,
            kek_version: result.kek_version,
        })
    }
}
