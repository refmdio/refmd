//! Create pending device command
//!
//! Creates a new pending device awaiting SAS verification.
//! Used when a user logs in from a new device.

use domain::encryption::{
    DeviceType, PendingDevice, PendingDeviceRepository, PublicKeyPair,
    UserIdentityPublicKeyRepository,
};
use domain::identity::UserId;
use std::sync::Arc;
use thiserror::Error;

/// Create pending device command
#[derive(Debug)]
pub struct CreatePendingDeviceCommand {
    pub user_id: UserId,
    pub device_name: String,
    pub device_type: DeviceType,
    /// X25519 ECDH public key (32 bytes)
    pub ecdh_public_key: Vec<u8>,
    /// Ed25519 signing public key (32 bytes)
    pub signing_public_key: Vec<u8>,
    /// Client-generated nonce for SAS (16 bytes)
    pub client_nonce: Vec<u8>,
}

/// Create pending device result
#[derive(Debug)]
pub struct CreatePendingDeviceResult {
    pub pending_device: PendingDevice,
    /// User's identity signing public key for SAS calculation on new device
    pub identity_signing_public_key: Vec<u8>,
}

/// Create pending device error
#[derive(Debug, Error)]
pub enum CreatePendingDeviceError<PDR: std::error::Error, UIPR: std::error::Error> {
    #[error("invalid device name: must be between 1 and 255 characters")]
    InvalidDeviceName,

    #[error("invalid ECDH public key: must be 32 bytes")]
    InvalidEcdhPublicKey,

    #[error("invalid signing public key: must be 32 bytes")]
    InvalidSigningPublicKey,

    #[error("invalid client nonce: must be 16 bytes")]
    InvalidClientNonce,

    #[error("identity public key not found")]
    IdentityPublicKeyNotFound,

    #[error("pending device repository error: {0}")]
    PendingDeviceRepository(PDR),

    #[error("identity public key repository error: {0}")]
    IdentityPublicKeyRepository(UIPR),
}

impl<PDR: std::error::Error, UIPR: std::error::Error> CreatePendingDeviceError<PDR, UIPR> {
    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            CreatePendingDeviceError::InvalidDeviceName
                | CreatePendingDeviceError::InvalidEcdhPublicKey
                | CreatePendingDeviceError::InvalidSigningPublicKey
                | CreatePendingDeviceError::InvalidClientNonce
        )
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, CreatePendingDeviceError::IdentityPublicKeyNotFound)
    }
}

/// Create pending device handler
pub struct CreatePendingDeviceHandler<PDR, UIPR> {
    pending_device_repo: Arc<PDR>,
    user_identity_public_key_repo: Arc<UIPR>,
}

impl<PDR, UIPR> CreatePendingDeviceHandler<PDR, UIPR>
where
    PDR: PendingDeviceRepository,
    UIPR: UserIdentityPublicKeyRepository,
{
    pub fn new(pending_device_repo: Arc<PDR>, user_identity_public_key_repo: Arc<UIPR>) -> Self {
        Self {
            pending_device_repo,
            user_identity_public_key_repo,
        }
    }

    pub async fn handle(
        &self,
        command: CreatePendingDeviceCommand,
    ) -> Result<CreatePendingDeviceResult, CreatePendingDeviceError<PDR::Error, UIPR::Error>> {
        // Validate device name
        if command.device_name.is_empty() || command.device_name.len() > 255 {
            return Err(CreatePendingDeviceError::InvalidDeviceName);
        }

        // Validate public keys
        if command.ecdh_public_key.len() != 32 {
            return Err(CreatePendingDeviceError::InvalidEcdhPublicKey);
        }

        if command.signing_public_key.len() != 32 {
            return Err(CreatePendingDeviceError::InvalidSigningPublicKey);
        }

        // Validate client nonce
        if command.client_nonce.len() != 16 {
            return Err(CreatePendingDeviceError::InvalidClientNonce);
        }

        // Fetch user's identity public key for SAS calculation on new device
        let identity_public_key = self
            .user_identity_public_key_repo
            .find_by_user_id(command.user_id)
            .await
            .map_err(CreatePendingDeviceError::IdentityPublicKeyRepository)?
            .ok_or(CreatePendingDeviceError::IdentityPublicKeyNotFound)?;

        // Create pending device
        let public_keys = PublicKeyPair::new(command.ecdh_public_key, command.signing_public_key);

        let pending_device = PendingDevice::new(
            command.user_id,
            command.device_name,
            command.device_type,
            public_keys,
            command.client_nonce,
        );

        // Save to repository
        self.pending_device_repo
            .save(&pending_device)
            .await
            .map_err(CreatePendingDeviceError::PendingDeviceRepository)?;

        Ok(CreatePendingDeviceResult {
            pending_device,
            identity_signing_public_key: identity_public_key.signing_public_key,
        })
    }
}
