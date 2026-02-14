//! Distribute UMK command
//!
//! Distributes the User Master Key to a newly approved device.
//! An existing device encrypts the UMK with the new device's public key.

use crate::dto::DeviceEncryptedUmkDto;
use crate::events::DeviceEventPublisher;
use domain::encryption::{
    DeviceEncryptedUMK, DeviceEncryptedUMKRepository, DeviceId, DeviceRepository,
};
use domain::identity::UserId;
use std::sync::Arc;
use thiserror::Error;

/// Distribute UMK command
#[derive(Debug)]
pub struct DistributeUmkCommand {
    /// User ID
    pub user_id: UserId,
    /// Target device ID (receiving the UMK)
    pub target_device_id: DeviceId,
    /// Sender device ID (providing the UMK)
    pub sender_device_id: DeviceId,
    /// PoP-authenticated device ID — must match `sender_device_id`
    pub authenticated_device_id: DeviceId,
    /// UMK encrypted with target device's public key
    pub encrypted_umk: Vec<u8>,
    /// Encryption nonce
    pub nonce: Vec<u8>,
}

/// Distribute UMK result
#[derive(Debug)]
pub struct DistributeUmkResult {
    pub device_encrypted_umk: DeviceEncryptedUmkDto,
}

/// Distribute UMK error
#[derive(Debug, Error)]
pub enum DistributeUmkError<DR: std::error::Error, UMKR: std::error::Error> {
    #[error("sender_device_id does not match authenticated device")]
    SenderDeviceMismatch,

    #[error("target device not found")]
    TargetDeviceNotFound,

    #[error("sender device not found")]
    SenderDeviceNotFound,

    #[error("target device has been revoked")]
    TargetDeviceRevoked,

    #[error("sender device has been revoked")]
    SenderDeviceRevoked,

    #[error("invalid nonce: must be 24 bytes")]
    InvalidNonce,

    #[error("device repository error: {0}")]
    DeviceRepository(DR),

    #[error("encrypted UMK repository error: {0}")]
    EncryptedUmkRepository(UMKR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, UMKR: std::error::Error] DistributeUmkError<DR, UMKR>,
    not_found: [DistributeUmkError::TargetDeviceNotFound, DistributeUmkError::SenderDeviceNotFound],
    access_denied: [DistributeUmkError::SenderDeviceMismatch],
    invalid_input: [
        DistributeUmkError::TargetDeviceRevoked,
        DistributeUmkError::SenderDeviceRevoked,
        DistributeUmkError::InvalidNonce,
    ],
);

/// XChaCha20-Poly1305 nonce size
const XCHACHA20_NONCE_SIZE: usize = 24;

/// Distribute UMK handler
pub struct DistributeUmkHandler<DR: ?Sized, UMKR: ?Sized> {
    device_repo: Arc<DR>,
    encrypted_umk_repo: Arc<UMKR>,
    event_publisher: Arc<dyn DeviceEventPublisher>,
}

impl<DR, UMKR> DistributeUmkHandler<DR, UMKR>
where
    DR: DeviceRepository + ?Sized,
    UMKR: DeviceEncryptedUMKRepository + ?Sized,
{
    pub fn new(
        device_repo: Arc<DR>,
        encrypted_umk_repo: Arc<UMKR>,
        event_publisher: Arc<dyn DeviceEventPublisher>,
    ) -> Self {
        Self {
            device_repo,
            encrypted_umk_repo,
            event_publisher,
        }
    }

    pub async fn handle(
        &self,
        command: DistributeUmkCommand,
    ) -> Result<DistributeUmkResult, DistributeUmkError<DR::Error, UMKR::Error>> {
        // Validate nonce length
        if command.nonce.len() != XCHACHA20_NONCE_SIZE {
            return Err(DistributeUmkError::InvalidNonce);
        }

        use crate::util::device_ownership::verify_pop_sender_and_devices;

        // Enforce PoP sender-device binding and verify both devices
        verify_pop_sender_and_devices(
            &self.device_repo,
            command.user_id,
            command.target_device_id,
            command.sender_device_id,
            command.authenticated_device_id,
        )
        .await
        .map_err(|e| {
            e.map_to(
                || DistributeUmkError::SenderDeviceMismatch,
                || DistributeUmkError::TargetDeviceNotFound,
                || DistributeUmkError::TargetDeviceRevoked,
                DistributeUmkError::DeviceRepository,
                || DistributeUmkError::SenderDeviceNotFound,
                || DistributeUmkError::SenderDeviceRevoked,
                DistributeUmkError::DeviceRepository,
            )
        })?;

        // Create and save encrypted UMK
        let device_encrypted_umk = DeviceEncryptedUMK::new(
            command.user_id,
            command.target_device_id,
            command.sender_device_id,
            command.encrypted_umk,
            command.nonce,
        );

        self.encrypted_umk_repo
            .save(&device_encrypted_umk)
            .await
            .map_err(DistributeUmkError::EncryptedUmkRepository)?;

        // Notify the new device that UMK is available
        self.event_publisher
            .pending_approved(
                command.target_device_id,
                command.user_id,
                command.target_device_id,
            )
            .await;

        Ok(DistributeUmkResult {
            device_encrypted_umk: device_encrypted_umk.into(),
        })
    }
}
