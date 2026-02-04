//! Distribute UMK command
//!
//! Distributes the User Master Key to a newly approved device.
//! An existing device encrypts the UMK with the new device's public key.

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
    /// UMK encrypted with target device's public key
    pub encrypted_umk: Vec<u8>,
    /// Encryption nonce
    pub nonce: Vec<u8>,
}

/// Distribute UMK result
#[derive(Debug)]
pub struct DistributeUmkResult {
    pub device_encrypted_umk: DeviceEncryptedUMK,
}

/// Distribute UMK error
#[derive(Debug, Error)]
pub enum DistributeUmkError<DR: std::error::Error, UMKR: std::error::Error> {
    #[error("target device not found")]
    TargetDeviceNotFound,

    #[error("sender device not found")]
    SenderDeviceNotFound,

    #[error("target device does not belong to this user")]
    TargetNotOwned,

    #[error("sender device does not belong to this user")]
    SenderNotOwned,

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

impl<DR: std::error::Error, UMKR: std::error::Error> DistributeUmkError<DR, UMKR> {
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            DistributeUmkError::TargetDeviceNotFound | DistributeUmkError::SenderDeviceNotFound
        )
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            DistributeUmkError::TargetNotOwned | DistributeUmkError::SenderNotOwned
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            DistributeUmkError::TargetDeviceRevoked
                | DistributeUmkError::SenderDeviceRevoked
                | DistributeUmkError::InvalidNonce
        )
    }
}

/// XChaCha20-Poly1305 nonce size
const XCHACHA20_NONCE_SIZE: usize = 24;

/// Distribute UMK handler
pub struct DistributeUmkHandler<DR, UMKR> {
    device_repo: Arc<DR>,
    encrypted_umk_repo: Arc<UMKR>,
}

impl<DR, UMKR> DistributeUmkHandler<DR, UMKR>
where
    DR: DeviceRepository,
    UMKR: DeviceEncryptedUMKRepository,
{
    pub fn new(device_repo: Arc<DR>, encrypted_umk_repo: Arc<UMKR>) -> Self {
        Self {
            device_repo,
            encrypted_umk_repo,
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

        // Verify target device exists and belongs to user
        let target_device = self
            .device_repo
            .find_by_id(command.target_device_id)
            .await
            .map_err(DistributeUmkError::DeviceRepository)?
            .ok_or(DistributeUmkError::TargetDeviceNotFound)?;

        if target_device.user_id != command.user_id {
            return Err(DistributeUmkError::TargetNotOwned);
        }

        if target_device.is_revoked() {
            return Err(DistributeUmkError::TargetDeviceRevoked);
        }

        // Verify sender device exists and belongs to user
        let sender_device = self
            .device_repo
            .find_by_id(command.sender_device_id)
            .await
            .map_err(DistributeUmkError::DeviceRepository)?
            .ok_or(DistributeUmkError::SenderDeviceNotFound)?;

        if sender_device.user_id != command.user_id {
            return Err(DistributeUmkError::SenderNotOwned);
        }

        if sender_device.is_revoked() {
            return Err(DistributeUmkError::SenderDeviceRevoked);
        }

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

        Ok(DistributeUmkResult { device_encrypted_umk })
    }
}
