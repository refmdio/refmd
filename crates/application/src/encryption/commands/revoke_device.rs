//! Revoke device command
//!
//! Handles device revocation business logic including:
//! - Signature verification
//! - Device revocation
//! - KEK/DEK rotation marking
//!
//! The handler has 6 type parameters because device revocation is a cross-cutting
//! operation that must verify identity signatures, revoke devices,
//! record audit events, and best-effort mark KEK/DEK rotation across all
//! affected workspaces and documents.

use domain::document::DocumentRepository;
use domain::encryption::{
    DeviceId, DeviceRepository, DeviceRevocationEvent, DeviceRevocationEventRepository,
    DocumentEncryptedKeyRepository, RevocationMode, UserIdentityPublicKeyRepository,
};
use domain::identity::UserId;
use domain::workspace::WorkspaceMemberRepository;
use std::sync::Arc;
use thiserror::Error;

use crate::encryption::services::mark_rotation::{MarkRotationResult, MarkRotationService};
use crate::encryption::services::rotation_marking_service::RotationMarkingService;

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
    /// Revocation mode: security (lost/compromised) or retire (safe disposal)
    pub revocation_mode: RevocationMode,
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

    #[error("document repository error: {0}")]
    DocumentRepository(DocR),

    #[error("document key repository error: {0}")]
    DocumentKeyRepository(DKR),

    #[error("failed to save audit event for device revocation: {0}")]
    AuditEventFailed(String),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, UIPK: std::error::Error, DRER: std::error::Error, WMR: std::error::Error, DocR: std::error::Error, DKR: std::error::Error]
    RevokeDeviceError<DR, UIPK, DRER, WMR, DocR, DKR>,
    not_found: [
        RevokeDeviceError::DeviceNotFound,
        RevokeDeviceError::IdentityPublicKeyNotFound,
    ],
    access_denied: [RevokeDeviceError::NotOwner],
    invalid_input: [
        RevokeDeviceError::TimestampOutOfRange,
        RevokeDeviceError::InvalidIdentityPublicKey,
        RevokeDeviceError::InvalidSignatureFormat,
        RevokeDeviceError::SignatureVerificationFailed,
        RevokeDeviceError::CannotRevokeSelf,
        RevokeDeviceError::AlreadyRevoked,
    ],
);

// Note: The RevokeDeviceError type parameter count stays at 6 (no WR, no WIR) because
// workspace rotation marking and invitation revocation are handled internally by
// RotationMarkingService (best-effort, non-atomic) via targeted UPDATEs.

/// Handler for the device revocation command.
///
/// This handler has 6 repository dependencies + 1 service, which is expected in a
/// CQRS architecture because device revocation is a cross-cutting operation that must:
/// - Verify the revoking user's identity signature (`identity_pk_repo`)
/// - Revoke the target device itself (`device_repo`)
/// - Record the revocation event for audit purposes (`revocation_event_repo`)
/// - Look up all workspaces the user belongs to (`workspace_member_repo`)
/// - Find all documents in affected workspaces (`document_repo`)
/// - Determine current DEK versions for rotation (`document_key_repo`)
/// - Best-effort mark workspace rotation + revoke invitations (`rotation_marking_service`)
pub struct RevokeDeviceHandler<DR: ?Sized, UIPK: ?Sized, DRER: ?Sized, WMR: ?Sized, DocR: ?Sized, DKR: ?Sized> {
    device_repo: Arc<DR>,
    identity_pk_repo: Arc<UIPK>,
    revocation_event_repo: Arc<DRER>,
    workspace_member_repo: Arc<WMR>,
    document_repo: Arc<DocR>,
    document_key_repo: Arc<DKR>,
    rotation_marking_service: Arc<dyn RotationMarkingService>,
}

impl<DR, UIPK, DRER, WMR, DocR, DKR> RevokeDeviceHandler<DR, UIPK, DRER, WMR, DocR, DKR>
where
    DR: DeviceRepository + ?Sized,
    UIPK: UserIdentityPublicKeyRepository + ?Sized,
    DRER: DeviceRevocationEventRepository + ?Sized,
    WMR: WorkspaceMemberRepository + ?Sized,
    DocR: DocumentRepository + ?Sized,
    DKR: DocumentEncryptedKeyRepository + ?Sized,
{
    pub fn new(
        device_repo: Arc<DR>,
        identity_pk_repo: Arc<UIPK>,
        revocation_event_repo: Arc<DRER>,
        workspace_member_repo: Arc<WMR>,
        document_repo: Arc<DocR>,
        document_key_repo: Arc<DKR>,
        rotation_marking_service: Arc<dyn RotationMarkingService>,
    ) -> Self {
        Self {
            device_repo,
            identity_pk_repo,
            revocation_event_repo,
            workspace_member_repo,
            document_repo,
            document_key_repo,
            rotation_marking_service,
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
        RevokeDeviceError<DR::Error, UIPK::Error, DRER::Error, WMR::Error, DocR::Error, DKR::Error>,
    > {
        // Phase 1: Validate and verify
        let (mut device, revocation_event) = self.validate_and_verify(&command).await?;

        // Phase 2: Execute revocation
        self.execute_revocation(&mut device, &revocation_event).await?;

        // Phase 3: Best-effort rotation marking.
        // Uses match for exhaustive coverage — adding a new RevocationMode variant
        // forces explicit handling of rotation behavior.
        match command.revocation_mode {
            RevocationMode::Security => {
                Ok(self.mark_rotation_best_effort(command.user_id).await)
            }
            RevocationMode::Retire => {
                // retire mode skips rotation — the device's private key is not compromised.
                Ok(MarkRotationResult {
                    workspaces_needing_kek_rotation: Vec::new(),
                    documents_needing_dek_rotation: Vec::new(),
                    revoked_invitation_count: 0,
                    rotation_marking_failures: None,
                })
            }
        }
    }

    /// Phase 3 wrapper: best-effort KEK/DEK rotation marking.
    ///
    /// **Design decision**: rotation marking is intentionally non-atomic with device
    /// revocation. The device is already revoked and its access is already denied.
    /// If rotation marking fails, the device is still revoked (primary security goal
    /// achieved). A background reconciliation job can detect and retry missed markers.
    ///
    /// This mirrors the member removal pattern (see `remove_member.rs`).
    /// Making this atomic would mean a transient rotation failure causes the handler
    /// to return an error. Because the device is already revoked, retrying would hit
    /// `AlreadyRevoked`, leaving rotation permanently un-marked — a worse outcome.
    async fn mark_rotation_best_effort(
        &self,
        user_id: UserId,
    ) -> RevokeDeviceResult {
        let service = MarkRotationService::new(
            self.workspace_member_repo.clone(),
            self.document_repo.clone(),
            self.document_key_repo.clone(),
            self.rotation_marking_service.clone(),
        );

        match service.mark_for_user(user_id).await {
            Ok(result) => {
                if let Some(ref failures) = result.rotation_marking_failures {
                    tracing::warn!(
                        user_id = %user_id,
                        failed_workspaces = ?failures.failed_workspace_ids,
                        failed_documents = ?failures.failed_document_ids,
                        "partial rotation marking failures after device revocation"
                    );
                } else {
                    tracing::info!(
                        user_id = %user_id,
                        revoked_invitations = result.revoked_invitation_count,
                        "KEK/DEK rotation marked after device revocation"
                    );
                }
                result
            }
            Err(e) => {
                tracing::error!(
                    user_id = %user_id,
                    error = %e,
                    "failed to mark KEK/DEK rotation after device revocation — \
                     background reconciliation will retry"
                );
                MarkRotationResult {
                    workspaces_needing_kek_rotation: Vec::new(),
                    documents_needing_dek_rotation: Vec::new(),
                    revoked_invitation_count: 0,
                    rotation_marking_failures: None,
                }
            }
        }
    }

    /// Phase 1: Timestamp validation, ownership check, signature verification.
    ///
    /// Returns the device (for revocation) and the revocation event (for audit).
    async fn validate_and_verify(
        &self,
        command: &RevokeDeviceCommand,
    ) -> Result<
        (domain::encryption::Device, DeviceRevocationEvent),
        RevokeDeviceError<DR::Error, UIPK::Error, DRER::Error, WMR::Error, DocR::Error, DKR::Error>,
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
            command.revocation_mode,
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
        RevokeDeviceError<DR::Error, UIPK::Error, DRER::Error, WMR::Error, DocR::Error, DKR::Error>,
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

}
