//! Revoke device command
//!
//! Handles device revocation business logic including:
//! - Signature verification
//! - Device revocation
//! - KEK/DEK rotation marking
//!
//! The handler has 7 type parameters because device revocation is a cross-cutting
//! operation that must atomically verify identity signatures, revoke devices,
//! record audit events, and mark KEK/DEK rotation across all affected workspaces
//! and documents.

use domain::document::DocumentRepository;
use domain::encryption::{
    DeviceId, DeviceRepository, DeviceRevocationEvent, DeviceRevocationEventRepository,
    DocumentEncryptedKeyRepository, UserIdentityPublicKeyRepository,
};
use domain::identity::UserId;
use domain::workspace::{WorkspaceMemberRepository, WorkspaceRepository};
use std::sync::Arc;
use thiserror::Error;

use crate::encryption::services::mark_rotation::{MarkRotationResult, MarkRotationService};

/// Revoke device command
#[derive(Debug)]
pub struct RevokeDeviceCommand {
    /// User performing the revocation
    pub user_id: UserId,
    /// Device to revoke
    pub device_id: DeviceId,
    /// Device performing the revocation (current device, from PoP)
    pub revoking_device_id: DeviceId,
    /// Client-provided revocation timestamp (Unix ms)
    pub revoked_at: i64,
    /// Ed25519 identity signature over the revocation event
    pub identity_signature: Vec<u8>,
    /// Current device's session device_id (to prevent self-revocation)
    pub session_device_id: Option<DeviceId>,
}

/// Revoke device result — delegates rotation data to [`MarkRotationResult`].
pub type RevokeDeviceResult = MarkRotationResult;

/// Revoke device error
#[derive(Debug, Error)]
pub enum RevokeDeviceError<
    DR: std::error::Error,
    UIPK: std::error::Error,
    DRER: std::error::Error,
    WMR: std::error::Error,
    WR: std::error::Error,
    DocR: std::error::Error,
    DKR: std::error::Error,
> {
    #[error("device not found")]
    DeviceNotFound,

    #[error("device is already revoked")]
    AlreadyRevoked,

    #[error("device does not belong to this user")]
    NotOwner,

    #[error("cannot revoke current device")]
    CannotRevokeSelf,

    #[error("invalid timestamp: out of range")]
    TimestampOutOfRange,

    #[error("invalid identity public key")]
    InvalidIdentityPublicKey,

    #[error("identity public key not found")]
    IdentityPublicKeyNotFound,

    #[error("invalid signature format")]
    InvalidSignatureFormat,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("device repository error: {0}")]
    DeviceRepository(DR),

    #[error("identity public key repository error: {0}")]
    IdentityPublicKeyRepository(UIPK),

    #[error("revocation event repository error: {0}")]
    RevocationEventRepository(DRER),

    #[error("workspace member repository error: {0}")]
    WorkspaceMemberRepository(WMR),

    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),

    #[error("document repository error: {0}")]
    DocumentRepository(DocR),

    #[error("document key repository error: {0}")]
    DocumentKeyRepository(DKR),

    #[error("failed to save audit event for device revocation: {0}")]
    AuditEventFailed(String),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, UIPK: std::error::Error, DRER: std::error::Error, WMR: std::error::Error, WR: std::error::Error, DocR: std::error::Error, DKR: std::error::Error]
    RevokeDeviceError<DR, UIPK, DRER, WMR, WR, DocR, DKR>,
    not_found: [RevokeDeviceError::DeviceNotFound],
    access_denied: [RevokeDeviceError::NotOwner],
    invalid_input: [
        RevokeDeviceError::TimestampOutOfRange,
        RevokeDeviceError::InvalidSignatureFormat,
        RevokeDeviceError::SignatureVerificationFailed,
        RevokeDeviceError::CannotRevokeSelf,
        RevokeDeviceError::AlreadyRevoked,
    ],
);

/// Handler for the device revocation command.
///
/// This handler has 7 repository dependencies, which is expected in a CQRS architecture
/// because device revocation is a cross-cutting operation that must atomically:
/// - Verify the revoking user's identity signature (`identity_pk_repo`)
/// - Revoke the target device itself (`device_repo`)
/// - Record the revocation event for audit purposes (`revocation_event_repo`)
/// - Look up all workspaces the user belongs to (`workspace_member_repo`)
/// - Mark each workspace for KEK rotation (`workspace_repo`)
/// - Find all documents in affected workspaces (`document_repo`)
/// - Determine current DEK versions for rotation (`document_key_repo`)
pub struct RevokeDeviceHandler<DR: ?Sized, UIPK: ?Sized, DRER: ?Sized, WMR: ?Sized, WR: ?Sized, DocR: ?Sized, DKR: ?Sized> {
    device_repo: Arc<DR>,
    identity_pk_repo: Arc<UIPK>,
    revocation_event_repo: Arc<DRER>,
    workspace_member_repo: Arc<WMR>,
    workspace_repo: Arc<WR>,
    document_repo: Arc<DocR>,
    document_key_repo: Arc<DKR>,
}

impl<DR, UIPK, DRER, WMR, WR, DocR, DKR> RevokeDeviceHandler<DR, UIPK, DRER, WMR, WR, DocR, DKR>
where
    DR: DeviceRepository + ?Sized,
    UIPK: UserIdentityPublicKeyRepository + ?Sized,
    DRER: DeviceRevocationEventRepository + ?Sized,
    WMR: WorkspaceMemberRepository + ?Sized,
    WR: WorkspaceRepository + ?Sized,
    DocR: DocumentRepository + ?Sized,
    DKR: DocumentEncryptedKeyRepository + ?Sized,
{
    pub fn new(
        device_repo: Arc<DR>,
        identity_pk_repo: Arc<UIPK>,
        revocation_event_repo: Arc<DRER>,
        workspace_member_repo: Arc<WMR>,
        workspace_repo: Arc<WR>,
        document_repo: Arc<DocR>,
        document_key_repo: Arc<DKR>,
    ) -> Self {
        Self {
            device_repo,
            identity_pk_repo,
            revocation_event_repo,
            workspace_member_repo,
            workspace_repo,
            document_repo,
            document_key_repo,
        }
    }

    /// Execute device revocation in three sequential phases:
    ///
    /// 1. **Validation**: Timestamp, ownership, signature verification.
    /// 2. **Revocation**: Audit event + device revoke.
    /// 3. **Rotation marking**: Best-effort KEK/DEK rotation markers.
    pub async fn handle(
        &self,
        command: RevokeDeviceCommand,
    ) -> Result<
        RevokeDeviceResult,
        RevokeDeviceError<DR::Error, UIPK::Error, DRER::Error, WMR::Error, WR::Error, DocR::Error, DKR::Error>,
    > {
        // Phase 1: Validate and verify
        let (mut device, revocation_event) = self.validate_and_verify(&command).await?;

        // Phase 2: Execute revocation
        self.execute_revocation(&mut device, &revocation_event).await?;

        // Phase 3: Mark rotation (best-effort)
        self.mark_rotation(command.user_id).await
    }

    /// Phase 1: Timestamp validation, ownership check, signature verification.
    ///
    /// Returns the device (for revocation) and the revocation event (for audit).
    async fn validate_and_verify(
        &self,
        command: &RevokeDeviceCommand,
    ) -> Result<
        (domain::encryption::Device, DeviceRevocationEvent),
        RevokeDeviceError<DR::Error, UIPK::Error, DRER::Error, WMR::Error, WR::Error, DocR::Error, DKR::Error>,
    > {
        // Validate timestamp (within 5 minutes)
        let now = chrono::Utc::now().timestamp_millis();
        let five_minutes_ms = 5 * 60 * 1000;
        if (command.revoked_at - now).abs() > five_minutes_ms {
            return Err(RevokeDeviceError::TimestampOutOfRange);
        }

        // Prevent revoking current device (check both session-bound and PoP-attested device)
        if command.session_device_id == Some(command.device_id)
            || command.revoking_device_id == command.device_id
        {
            return Err(RevokeDeviceError::CannotRevokeSelf);
        }

        // Find device
        let device = self
            .device_repo
            .find_by_id(command.device_id)
            .await
            .map_err(RevokeDeviceError::DeviceRepository)?
            .ok_or(RevokeDeviceError::DeviceNotFound)?;

        // Reject already-revoked devices to preserve the original revoked_at timestamp
        if device.is_revoked() {
            return Err(RevokeDeviceError::AlreadyRevoked);
        }

        // Verify ownership
        if device.user_id != command.user_id {
            return Err(RevokeDeviceError::NotOwner);
        }

        // Build revocation event
        let revocation_event = DeviceRevocationEvent::new(
            command.user_id,
            command.device_id,
            command.revoking_device_id,
            command.revoked_at,
            command.identity_signature.clone(),
        );

        // Get identity public key
        let identity_pk = self
            .identity_pk_repo
            .find_by_user_id(command.user_id)
            .await
            .map_err(RevokeDeviceError::IdentityPublicKeyRepository)?
            .ok_or(RevokeDeviceError::IdentityPublicKeyNotFound)?;

        // Verify Ed25519 signature
        let message = revocation_event
            .signature_payload()
            .map_err(|_| RevokeDeviceError::SignatureVerificationFailed)?;

        use crate::util::signature_verification::{verify_ed25519_signature, map_sig_error};
        verify_ed25519_signature(
            &identity_pk.signing_public_key,
            &command.identity_signature,
            &message,
        )
        .map_err(|e| map_sig_error(
            e,
            || RevokeDeviceError::InvalidIdentityPublicKey,
            || RevokeDeviceError::InvalidSignatureFormat,
            || RevokeDeviceError::SignatureVerificationFailed,
        ))?;

        Ok((device, revocation_event))
    }

    /// Phase 2: Persist audit event and revoke the device.
    async fn execute_revocation(
        &self,
        device: &mut domain::encryption::Device,
        revocation_event: &DeviceRevocationEvent,
    ) -> Result<
        (),
        RevokeDeviceError<DR::Error, UIPK::Error, DRER::Error, WMR::Error, WR::Error, DocR::Error, DKR::Error>,
    > {
        // Save revocation event (audit trail - must succeed before proceeding)
        self.revocation_event_repo
            .save(revocation_event)
            .await
            .map_err(|e| {
                tracing::error!("failed to save device revocation event: {}", e);
                RevokeDeviceError::AuditEventFailed(e.to_string())
            })?;

        // Revoke device
        device.revoke();
        self.device_repo
            .save(device)
            .await
            .map_err(RevokeDeviceError::DeviceRepository)?;

        Ok(())
    }

    /// Phase 3: Best-effort KEK/DEK rotation marking.
    ///
    /// The device is already revoked at this point. Delegates to
    /// [`MarkRotationService`] so the same logic can be reused by other
    /// rotation triggers (e.g., scheduled rotation, member removal).
    async fn mark_rotation(
        &self,
        user_id: UserId,
    ) -> Result<
        RevokeDeviceResult,
        RevokeDeviceError<DR::Error, UIPK::Error, DRER::Error, WMR::Error, WR::Error, DocR::Error, DKR::Error>,
    > {
        let service = MarkRotationService::new(
            self.workspace_member_repo.clone(),
            self.workspace_repo.clone(),
            self.document_repo.clone(),
            self.document_key_repo.clone(),
        );

        service
            .mark_for_user(user_id)
            .await
            .map_err(|e| match e {
                crate::encryption::services::mark_rotation::MarkRotationError::WorkspaceMemberRepository(inner) => {
                    RevokeDeviceError::WorkspaceMemberRepository(inner)
                }
            })
    }
}
