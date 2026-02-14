//! Create pending device command
//!
//! Creates a new pending device awaiting SAS verification.
//! Used when a user logs in from a new device.

use crate::dto::PendingDeviceDto;
use crate::events::DeviceEventPublisher;
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
    /// IP address of the requesting device
    pub ip_address: Option<String>,
}

/// Create pending device result
#[derive(Debug)]
pub struct CreatePendingDeviceResult {
    pub pending_device: PendingDeviceDto,
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

crate::types::impl_app_error!(
    [PDR: std::error::Error, UIPR: std::error::Error]
    CreatePendingDeviceError<PDR, UIPR>,
    not_found: [CreatePendingDeviceError::IdentityPublicKeyNotFound],
    invalid_input: [
        CreatePendingDeviceError::InvalidDeviceName,
        CreatePendingDeviceError::InvalidEcdhPublicKey,
        CreatePendingDeviceError::InvalidSigningPublicKey,
        CreatePendingDeviceError::InvalidClientNonce,
    ],
);

/// Create pending device handler
pub struct CreatePendingDeviceHandler<PDR: ?Sized, UIPR: ?Sized> {
    pending_device_repo: Arc<PDR>,
    user_identity_public_key_repo: Arc<UIPR>,
    event_publisher: Arc<dyn DeviceEventPublisher>,
}

impl<PDR, UIPR> CreatePendingDeviceHandler<PDR, UIPR>
where
    PDR: PendingDeviceRepository + ?Sized,
    UIPR: UserIdentityPublicKeyRepository + ?Sized,
{
    pub fn new(
        pending_device_repo: Arc<PDR>,
        user_identity_public_key_repo: Arc<UIPR>,
        event_publisher: Arc<dyn DeviceEventPublisher>,
    ) -> Self {
        Self {
            pending_device_repo,
            user_identity_public_key_repo,
            event_publisher,
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

        // Validate public keys (length + low-order / small-order point rejection)
        // NOTE: Presentation layer also validates (defense-in-depth).
        // These checks remain as transport-independent business-rule preconditions.
        use domain::crypto_validation::{is_valid_x25519_public_key, is_valid_ed25519_public_key};
        if command.ecdh_public_key.len() != 32
            || !is_valid_x25519_public_key(&command.ecdh_public_key)
        {
            return Err(CreatePendingDeviceError::InvalidEcdhPublicKey);
        }

        if command.signing_public_key.len() != 32
            || !is_valid_ed25519_public_key(&command.signing_public_key)
        {
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
            command.ip_address,
        );

        // Save to repository
        self.pending_device_repo
            .save(&pending_device)
            .await
            .map_err(CreatePendingDeviceError::PendingDeviceRepository)?;

        let result: CreatePendingDeviceResult = CreatePendingDeviceResult {
            pending_device: pending_device.into(),
            identity_signing_public_key: identity_public_key.signing_public_key,
        };

        // Publish SSE event for existing devices
        self.event_publisher
            .pending_created(
                result.pending_device.id,
                command.user_id,
                result.pending_device.name.clone(),
                command.device_type,
                result.pending_device.ip_address.clone(),
                result.pending_device.expires_at,
            )
            .await;

        Ok(result)
    }
}
