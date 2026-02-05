//! Approve device command
//!
//! Promotes a pending device to a full device after SAS verification.
//! Requires the existing device to sign the pending device's public keys.

use domain::encryption::{
    Device, DeviceId, DeviceRepository, PendingDeviceRepository, UserIdentityPublicKeyRepository,
};
use domain::identity::UserId;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
    pub device: Device,
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
    ApproveDeviceError<DR, PDR, UIPK>
{
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            ApproveDeviceError::PendingDeviceNotFound
                | ApproveDeviceError::IdentityPublicKeyNotFound
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            ApproveDeviceError::PendingDeviceExpired
                | ApproveDeviceError::InvalidSignatureLength
                | ApproveDeviceError::SignatureVerificationFailed
                | ApproveDeviceError::InvalidIdentityPublicKey
        )
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(self, ApproveDeviceError::NotOwner)
    }
}

/// Approve device handler
pub struct ApproveDeviceHandler<DR, PDR, UIPK> {
    device_repo: Arc<DR>,
    pending_device_repo: Arc<PDR>,
    identity_public_key_repo: Arc<UIPK>,
}

impl<DR, PDR, UIPK> ApproveDeviceHandler<DR, PDR, UIPK>
where
    DR: DeviceRepository,
    PDR: PendingDeviceRepository,
    UIPK: UserIdentityPublicKeyRepository,
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

        // Parse the identity signing public key (Ed25519, 32 bytes)
        let signing_pk_bytes: [u8; 32] = identity_key
            .signing_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ApproveDeviceError::InvalidIdentityPublicKey)?;

        let verifying_key = VerifyingKey::from_bytes(&signing_pk_bytes)
            .map_err(|_| ApproveDeviceError::InvalidIdentityPublicKey)?;

        // Build the message that was signed: device_signing_pk || device_ecdh_pk || client_nonce
        let mut message = Vec::new();
        message.extend_from_slice(&pending_device.signing_public_key);
        message.extend_from_slice(&pending_device.ecdh_public_key);
        message.extend_from_slice(&pending_device.client_nonce);

        // Parse and verify the signature
        let signature_bytes: [u8; 64] = command
            .identity_signature
            .as_slice()
            .try_into()
            .map_err(|_| ApproveDeviceError::InvalidSignatureLength)?;

        let signature = Signature::from_bytes(&signature_bytes);

        verifying_key
            .verify(&message, &signature)
            .map_err(|_| ApproveDeviceError::SignatureVerificationFailed)?;

        // Create device from pending device
        let device = Device::from_pending(pending_device.clone(), command.identity_signature);

        // Save device
        self.device_repo
            .save(&device)
            .await
            .map_err(ApproveDeviceError::DeviceRepository)?;

        // Delete pending device
        self.pending_device_repo
            .delete(command.pending_device_id)
            .await
            .map_err(ApproveDeviceError::PendingDeviceRepository)?;

        Ok(ApproveDeviceResult { device })
    }
}
