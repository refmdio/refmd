//! Create invitation command
//!
//! Creates a new workspace invitation. Requires PoP + member:invite permission.
//! Validates inputs, resolves role, checks escalation, then delegates to
//! InvitationCreationService for transactional kek_version + INSERT.

use crate::dto::WorkspaceInvitationDto;
use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use crate::workspace::InvitationCreationError;
use chrono::{DateTime, Duration, Utc};
use domain::identity::{Email, UserId};
use domain::workspace::{
    NewInvitationParams, RoleId, WorkspaceId, WorkspaceInvitation, WorkspaceMemberRepository,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository, permission,
};
use std::sync::Arc;
use thiserror::Error;

use super::super::InvitationCreationService;

/// base64url character set (no padding)
fn is_base64url_chars(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Create invitation command
#[derive(Debug)]
pub struct CreateInvitationCommand {
    pub workspace_id: WorkspaceId,
    pub invitation_id: domain::workspace::InvitationId,
    pub user_id: UserId,
    pub token_hash: String,
    pub token_prefix: String,
    pub role_id: Option<RoleId>,
    pub invited_email: String,
    pub encrypted_kek: Vec<u8>,
    pub kek_nonce: Vec<u8>,
    pub kek_version: i32,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Create invitation result
#[derive(Debug)]
pub struct CreateInvitationResult {
    pub invitation: WorkspaceInvitationDto,
}

/// Create invitation error
#[derive(Debug, Error)]
pub enum CreateInvitationError<
    MR: std::error::Error,
    RR: std::error::Error,
    RPR: std::error::Error,
> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("target role not found")]
    RoleNotFound,

    #[error("target role does not belong to this workspace")]
    RoleWorkspaceMismatch,

    #[error("cannot assign a role with higher privileges than your own")]
    RoleEscalation,

    /// Data integrity violation: every workspace must have a default role.
    /// Intentionally unclassified in impl_app_error! → falls through to 500 ISE.
    #[error("default role not found for workspace")]
    DefaultRoleNotFound,

    #[error("invalid token_hash format")]
    InvalidTokenHashFormat,

    #[error("invalid token_prefix format")]
    InvalidTokenPrefix,

    #[error("invalid encrypted_kek length: must be 48 bytes")]
    InvalidEncryptedKekLength,

    #[error("invalid kek_nonce length: must be 24 bytes")]
    InvalidNonceLength,

    #[error("expiration must be in the future")]
    InvalidExpiration,

    #[error("expiration must not exceed 30 days from now")]
    ExpirationTooFar,

    #[error("invalid email format")]
    InvalidEmailFormat,

    #[error(transparent)]
    Creation(InvitationCreationError),
}

crate::types::impl_app_error!(
    [MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    CreateInvitationError<MR, RR, RPR>,
    not_found: [
        CreateInvitationError::WorkspaceAccess(WorkspaceAccessError::NotMember),
        CreateInvitationError::Creation(InvitationCreationError::WorkspaceNotFound),
    ],
    access_denied: [
        CreateInvitationError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
        CreateInvitationError::RoleEscalation,
    ],
    invalid_input: [
        CreateInvitationError::InvalidTokenHashFormat,
        CreateInvitationError::InvalidTokenPrefix,
        CreateInvitationError::InvalidEncryptedKekLength,
        CreateInvitationError::InvalidNonceLength,
        CreateInvitationError::InvalidExpiration,
        CreateInvitationError::ExpirationTooFar,
        CreateInvitationError::InvalidEmailFormat,
    ],
    conflict: [
        CreateInvitationError::Creation(InvitationCreationError::NeedsKekRotation),
        CreateInvitationError::Creation(InvitationCreationError::TokenHashConflict),
        CreateInvitationError::Creation(InvitationCreationError::InvitationIdConflict),
    ],
    unprocessable: [
        CreateInvitationError::RoleNotFound,
        CreateInvitationError::Creation(InvitationCreationError::KekVersionMismatch),
        CreateInvitationError::RoleWorkspaceMismatch,
        CreateInvitationError::Creation(InvitationCreationError::RoleDeleted),
    ],
);

/// Create invitation handler
pub struct CreateInvitationHandler<MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
    creation_service: Arc<dyn InvitationCreationService>,
}

impl<MR: ?Sized, RR: ?Sized, RPR: ?Sized> CreateInvitationHandler<MR, RR, RPR>
where
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
{
    pub fn new(
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
        creation_service: Arc<dyn InvitationCreationService>,
    ) -> Self {
        Self {
            member_repo,
            role_repo,
            role_perm_repo,
            creation_service,
        }
    }

    pub async fn handle(
        &self,
        command: CreateInvitationCommand,
    ) -> Result<CreateInvitationResult, CreateInvitationError<MR::Error, RR::Error, RPR::Error>>
    {
        // 1. Input validation
        // token_hash: 43 chars, base64url character set
        if command.token_hash.len() != 43 || !is_base64url_chars(&command.token_hash) {
            return Err(CreateInvitationError::InvalidTokenHashFormat);
        }
        // token_prefix: 4 chars, base64url character set
        if command.token_prefix.len() != 4 || !is_base64url_chars(&command.token_prefix) {
            return Err(CreateInvitationError::InvalidTokenPrefix);
        }
        // encrypted_kek: 48 bytes (32 KEK + 16 Poly1305 tag)
        if command.encrypted_kek.len() != 48 {
            return Err(CreateInvitationError::InvalidEncryptedKekLength);
        }
        // kek_nonce: 24 bytes (XChaCha20-Poly1305)
        if command.kek_nonce.len() != 24 {
            return Err(CreateInvitationError::InvalidNonceLength);
        }
        // expires_at: must be in future and ≤ NOW() + 30 days (default NOW() + 7 days)
        let expires_at = command
            .expires_at
            .unwrap_or_else(|| Utc::now() + Duration::days(7));
        if expires_at <= Utc::now() {
            return Err(CreateInvitationError::InvalidExpiration);
        }
        if expires_at > Utc::now() + Duration::days(30) {
            return Err(CreateInvitationError::ExpirationTooFar);
        }
        // invited_email: required, valid email format (normalize: trim + lowercase)
        let invited_email = Email::new(&command.invited_email)
            .map_err(|_| CreateInvitationError::InvalidEmailFormat)?
            .to_string();

        // 2. Permission check (member:invite)
        let actor = check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.workspace_id,
            command.user_id,
            permission::MEMBER_INVITE,
        )
        .await
        .map_err(CreateInvitationError::WorkspaceAccess)?;

        // 3. Resolve role_id (null → default role)
        let target_role = if let Some(role_id) = command.role_id {
            self.role_repo
                .find_by_id(role_id)
                .await
                .map_err(|e| {
                    CreateInvitationError::WorkspaceAccess(WorkspaceAccessError::RoleRepository(e))
                })?
                .ok_or(CreateInvitationError::RoleNotFound)?
        } else {
            // Find default role (is_default=true) for this workspace
            let roles = self
                .role_repo
                .find_by_workspace_id(command.workspace_id)
                .await
                .map_err(|e| {
                    CreateInvitationError::WorkspaceAccess(WorkspaceAccessError::RoleRepository(e))
                })?;
            roles
                .into_iter()
                .find(|r| r.is_default)
                .ok_or(CreateInvitationError::DefaultRoleNotFound)?
        };

        // 4. Role workspace mismatch (422 per design doc)
        if target_role.workspace_id != command.workspace_id {
            return Err(CreateInvitationError::RoleWorkspaceMismatch);
        }

        // 5. Role escalation prevention
        if permission::privilege_level(target_role.base_role)
            > permission::privilege_level(actor.role.base_role)
        {
            return Err(CreateInvitationError::RoleEscalation);
        }

        // 6. Build invitation entity
        let invitation = WorkspaceInvitation::new(NewInvitationParams {
            id: command.invitation_id,
            workspace_id: command.workspace_id,
            token_hash: command.token_hash,
            token_prefix: command.token_prefix,
            role_id: target_role.id,
            invited_by: command.user_id,
            invited_email,
            encrypted_kek: command.encrypted_kek,
            kek_nonce: command.kek_nonce,
            kek_version: command.kek_version,
            expires_at,
        });

        // 7. Transactional creation (FOR SHARE + kek_version check + INSERT)
        self.creation_service
            .create_atomic(&invitation)
            .await
            .map_err(CreateInvitationError::Creation)?;

        Ok(CreateInvitationResult {
            invitation: invitation.into(),
        })
    }
}
