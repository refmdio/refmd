//! Revoke device command
//!
//! Handles device revocation business logic including:
//! - Signature verification
//! - Device revocation
//! - KEK/DEK rotation marking

use domain::document::{DocumentRepository};
use domain::encryption::{
    DeviceId, DeviceRepository, DeviceRevocationEvent, DeviceRevocationEventRepository,
    DocumentEncryptedKeyRepository, UserIdentityPublicKeyRepository,
};
use domain::identity::UserId;
use domain::workspace::{WorkspaceMemberRepository, WorkspaceRepository};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::sync::Arc;
use thiserror::Error;

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

/// Documents grouped by workspace that need DEK rotation
#[derive(Debug)]
pub struct WorkspaceDocumentsForRotation {
    pub workspace_id: uuid::Uuid,
    pub document_ids: Vec<uuid::Uuid>,
}

/// Revoke device result
#[derive(Debug)]
pub struct RevokeDeviceResult {
    pub workspaces_needing_kek_rotation: Vec<uuid::Uuid>,
    pub documents_needing_dek_rotation: Vec<WorkspaceDocumentsForRotation>,
}

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

    #[error("key rotation marking failed: revocation succeeded but rotation markers could not be saved")]
    RotationMarkingFailed,
}

impl<DR: std::error::Error, UIPK: std::error::Error, DRER: std::error::Error, WMR: std::error::Error, WR: std::error::Error, DocR: std::error::Error, DKR: std::error::Error>
    RevokeDeviceError<DR, UIPK, DRER, WMR, WR, DocR, DKR>
{
    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            RevokeDeviceError::TimestampOutOfRange
                | RevokeDeviceError::InvalidSignatureFormat
                | RevokeDeviceError::SignatureVerificationFailed
                | RevokeDeviceError::CannotRevokeSelf
        )
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, RevokeDeviceError::DeviceNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(self, RevokeDeviceError::NotOwner)
    }
}

/// Revoke device handler
pub struct RevokeDeviceHandler<DR, UIPK, DRER: ?Sized, WMR, WR, DocR, DKR> {
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
    DR: DeviceRepository,
    UIPK: UserIdentityPublicKeyRepository,
    DRER: DeviceRevocationEventRepository + ?Sized,
    WMR: WorkspaceMemberRepository,
    WR: WorkspaceRepository,
    DocR: DocumentRepository,
    DKR: DocumentEncryptedKeyRepository,
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

    pub async fn handle(
        &self,
        command: RevokeDeviceCommand,
    ) -> Result<
        RevokeDeviceResult,
        RevokeDeviceError<DR::Error, UIPK::Error, DRER::Error, WMR::Error, WR::Error, DocR::Error, DKR::Error>,
    > {
        // Validate timestamp (within 5 minutes)
        let now = chrono::Utc::now().timestamp_millis();
        let five_minutes_ms = 5 * 60 * 1000;
        if (command.revoked_at - now).abs() > five_minutes_ms {
            return Err(RevokeDeviceError::TimestampOutOfRange);
        }

        // Prevent revoking current device
        if command.session_device_id == Some(command.device_id) {
            return Err(RevokeDeviceError::CannotRevokeSelf);
        }

        // Find device
        let mut device = self
            .device_repo
            .find_by_id(command.device_id)
            .await
            .map_err(RevokeDeviceError::DeviceRepository)?
            .ok_or(RevokeDeviceError::DeviceNotFound)?;

        // Verify ownership
        if device.user_id != command.user_id {
            return Err(RevokeDeviceError::NotOwner);
        }

        // Build revocation event and verify signature
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
        let pk_bytes: [u8; 32] = identity_pk
            .signing_public_key
            .as_slice()
            .try_into()
            .map_err(|_| RevokeDeviceError::InvalidIdentityPublicKey)?;

        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|_| RevokeDeviceError::InvalidIdentityPublicKey)?;

        let sig_bytes: [u8; 64] = command
            .identity_signature
            .as_slice()
            .try_into()
            .map_err(|_| RevokeDeviceError::InvalidSignatureFormat)?;

        let signature = Signature::from_bytes(&sig_bytes);

        let message = revocation_event.signature_payload();
        verifying_key
            .verify(&message, &signature)
            .map_err(|_| RevokeDeviceError::SignatureVerificationFailed)?;

        // Save revocation event (audit purposes)
        if let Err(e) = self.revocation_event_repo.save(&revocation_event).await {
            tracing::error!("failed to save device revocation event: {}", e);
        }

        // Revoke device
        device.revoke();
        self.device_repo
            .save(&device)
            .await
            .map_err(RevokeDeviceError::DeviceRepository)?;

        // Mark workspaces for KEK rotation and documents for DEK rotation
        let mut workspace_ids_needing_rotation = Vec::new();
        let mut documents_needing_rotation = Vec::new();

        let members = self
            .workspace_member_repo
            .find_by_user_id(command.user_id)
            .await
            .map_err(RevokeDeviceError::WorkspaceMemberRepository)?;

        for member in members {
            let workspace = self
                .workspace_repo
                .find_by_id(member.workspace_id)
                .await
                .map_err(RevokeDeviceError::WorkspaceRepository)?;

            let Some(mut workspace) = workspace else {
                continue;
            };

            workspace.mark_needs_kek_rotation();
            self.workspace_repo
                .save(&workspace)
                .await
                .map_err(|e| {
                    tracing::error!(
                        "failed to mark workspace {} for KEK rotation: {}",
                        workspace.id,
                        e
                    );
                    RevokeDeviceError::RotationMarkingFailed
                })?;
            workspace_ids_needing_rotation.push(workspace.id.as_uuid());

            let documents = self
                .document_repo
                .find_by_workspace_id(member.workspace_id)
                .await
                .map_err(RevokeDeviceError::DocumentRepository)?;

            let mut workspace_document_ids = Vec::new();
            for mut document in documents {
                document.mark_needs_dek_rotation();

                let keys = self
                    .document_key_repo
                    .find_by_document_id(document.id)
                    .await
                    .map_err(RevokeDeviceError::DocumentKeyRepository)?;

                let max_version = keys
                    .iter()
                    .map(|k| k.key_version.as_i32())
                    .max()
                    .unwrap_or(0);
                document.set_min_dek_version(max_version + 1);

                self.document_repo.save(&document).await.map_err(|e| {
                    tracing::error!(
                        "failed to mark document {} for DEK rotation: {}",
                        document.id,
                        e
                    );
                    RevokeDeviceError::RotationMarkingFailed
                })?;
                workspace_document_ids.push(document.id.as_uuid());
            }

            if !workspace_document_ids.is_empty() {
                documents_needing_rotation.push(WorkspaceDocumentsForRotation {
                    workspace_id: workspace.id.as_uuid(),
                    document_ids: workspace_document_ids,
                });
            }
        }

        Ok(RevokeDeviceResult {
            workspaces_needing_kek_rotation: workspace_ids_needing_rotation,
            documents_needing_dek_rotation: documents_needing_rotation,
        })
    }
}
