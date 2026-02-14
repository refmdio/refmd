//! Approve device command
//!
//! Promotes a pending device to a full device after SAS verification.
//! Requires the existing device to sign the pending device's public keys.

use crate::dto::DeviceDto;
use domain::encryption::{
    Device, DeviceId, DeviceRepository, PendingDeviceRepository, UserIdentityPublicKeyRepository,
};
use domain::identity::UserId;
use domain::signature::{build_signature_message, SignatureAction};
use serde::Serialize;
use std::sync::Arc;
use thiserror::Error;

/// Approve device command
#[derive(Debug)]
pub struct ApproveDeviceCommand {
    /// ID of the pending device to approve
    pub pending_device_id: DeviceId,
    /// User ID (for ownership validation)
    pub user_id: UserId,
    /// Identity signature from an existing device (Ed25519 signature)
    /// Signs: device_signing_pk || device_ecdh_pk || client_nonce
    pub identity_signature: Vec<u8>,
}

/// Approve device result
#[derive(Debug)]
pub struct ApproveDeviceResult {
    pub device: DeviceDto,
}

/// Approve device error
#[derive(Debug, Error)]
pub enum ApproveDeviceError<DR: std::error::Error, PDR: std::error::Error, UIPK: std::error::Error>
{
    #[error("pending device not found")]
    PendingDeviceNotFound,

    #[error("pending device has expired")]
    PendingDeviceExpired,

    #[error("pending device does not belong to this user")]
    NotOwner,

    #[error("invalid identity signature: must be 64 bytes")]
    InvalidSignatureLength,

    #[error("invalid identity signature: verification failed")]
    SignatureVerificationFailed,

    #[error("user identity public key not found")]
    IdentityPublicKeyNotFound,

    #[error("invalid identity public key format")]
    InvalidIdentityPublicKey,

    #[error("device repository error: {0}")]
    DeviceRepository(DR),

    #[error("pending device repository error: {0}")]
    PendingDeviceRepository(PDR),

    #[error("identity public key repository error: {0}")]
    IdentityPublicKeyRepository(UIPK),
}

impl<DR: std::error::Error, PDR: std::error::Error, UIPK: std::error::Error>
    crate::types::AppError for ApproveDeviceError<DR, PDR, UIPK>
{
    fn is_not_found(&self) -> bool {
        matches!(
            self,
            ApproveDeviceError::PendingDeviceNotFound
                | ApproveDeviceError::IdentityPublicKeyNotFound
        )
    }

    fn is_invalid_input(&self) -> bool {
        matches!(
            self,
            ApproveDeviceError::InvalidSignatureLength
                | ApproveDeviceError::SignatureVerificationFailed
                | ApproveDeviceError::InvalidIdentityPublicKey
        )
    }

    fn is_gone(&self) -> bool {
        matches!(self, ApproveDeviceError::PendingDeviceExpired)
    }

    fn is_access_denied(&self) -> bool {
        matches!(self, ApproveDeviceError::NotOwner)
    }
}

/// Approve device handler
pub struct ApproveDeviceHandler<DR: ?Sized, PDR: ?Sized, UIPK: ?Sized> {
    device_repo: Arc<DR>,
    pending_device_repo: Arc<PDR>,
    identity_public_key_repo: Arc<UIPK>,
}

impl<DR, PDR, UIPK> ApproveDeviceHandler<DR, PDR, UIPK>
where
    DR: DeviceRepository + ?Sized,
    PDR: PendingDeviceRepository + ?Sized,
    UIPK: UserIdentityPublicKeyRepository + ?Sized,
{
    pub fn new(
        device_repo: Arc<DR>,
        pending_device_repo: Arc<PDR>,
        identity_public_key_repo: Arc<UIPK>,
    ) -> Self {
        Self {
            device_repo,
            pending_device_repo,
            identity_public_key_repo,
        }
    }

    pub async fn handle(
        &self,
        command: ApproveDeviceCommand,
    ) -> Result<ApproveDeviceResult, ApproveDeviceError<DR::Error, PDR::Error, UIPK::Error>> {
        // Validate signature length (Ed25519 signature is 64 bytes)
        if command.identity_signature.len() != 64 {
            return Err(ApproveDeviceError::InvalidSignatureLength);
        }

        // Find pending device
        let pending_device = self
            .pending_device_repo
            .find_by_id(command.pending_device_id)
            .await
            .map_err(ApproveDeviceError::PendingDeviceRepository)?
            .ok_or(ApproveDeviceError::PendingDeviceNotFound)?;

        // Verify ownership
        if pending_device.user_id != command.user_id {
            return Err(ApproveDeviceError::NotOwner);
        }

        // Check expiration
        if pending_device.is_expired() {
            return Err(ApproveDeviceError::PendingDeviceExpired);
        }

        // Get user's identity signing public key for verification
        let identity_key = self
            .identity_public_key_repo
            .find_by_user_id(command.user_id)
            .await
            .map_err(ApproveDeviceError::IdentityPublicKeyRepository)?
            .ok_or(ApproveDeviceError::IdentityPublicKeyNotFound)?;

        // Build the signature message using signature protocol format
        #[derive(Serialize)]
        struct DeviceApprovalPayload {
            client_nonce: String,
            device_ecdh_public_key: String,
            device_signing_public_key: String,
        }

        let payload = DeviceApprovalPayload {
            device_signing_public_key: base64_url::encode(&pending_device.signing_public_key),
            device_ecdh_public_key: base64_url::encode(&pending_device.ecdh_public_key),
            client_nonce: base64_url::encode(&pending_device.client_nonce),
        };

        let message = build_signature_message(SignatureAction::DeviceApproval, &payload)
            .map_err(|_| ApproveDeviceError::SignatureVerificationFailed)?;

        // Verify identity signature over the approval message
        use crate::util::signature_verification::{verify_ed25519_signature, map_sig_error};
        verify_ed25519_signature(
            &identity_key.signing_public_key,
            &command.identity_signature,
            &message,
        )
        .map_err(|e| map_sig_error(
            e,
            || ApproveDeviceError::InvalidIdentityPublicKey,
            || ApproveDeviceError::InvalidSignatureLength,
            || ApproveDeviceError::SignatureVerificationFailed,
        ))?;

        // Create device from pending device
        let device = Device::from_pending(pending_device.clone(), command.identity_signature);

        // Save device
        self.device_repo
            .save(&device)
            .await
            .map_err(ApproveDeviceError::DeviceRepository)?;

        // Delete pending device (best-effort: approval already succeeded)
        if let Err(e) = self
            .pending_device_repo
            .delete(command.pending_device_id)
            .await
        {
            tracing::warn!(
                pending_device_id = %command.pending_device_id,
                "device approved but failed to delete pending record: {}",
                e
            );
        }

        Ok(ApproveDeviceResult { device: device.into() })
    }
}
