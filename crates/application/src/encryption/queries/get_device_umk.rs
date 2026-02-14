//! Get device UMK query
//!
//! Retrieves the encrypted UMK distributed to a device, along with the
//! sender device's public keys for shared-secret derivation.

use domain::encryption::{DeviceEncryptedUMKRepository, DeviceId, DeviceRepository};
use domain::identity::UserId;
use std::sync::Arc;
use thiserror::Error;

/// Get device UMK query
#[derive(Debug)]
pub struct GetDeviceUmkQuery {
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// The device ID verified via PoP — must match `device_id`.
    pub pop_device_id: DeviceId,
}

/// Get device UMK result
#[derive(Debug)]
pub struct GetDeviceUmkResult {
    pub sender_device_id: DeviceId,
    pub sender_ecdh_public_key: Vec<u8>,
    pub sender_signing_public_key: Vec<u8>,
    pub encrypted_umk: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Get device UMK error
#[derive(Debug, Error)]
pub enum GetDeviceUmkError<DR: std::error::Error, UR: std::error::Error> {
    #[error("device mismatch: can only fetch own UMK")]
    DeviceMismatch,

    #[error("device not found")]
    DeviceNotFound,

    /// Security: uses "device not found" message to prevent leaking revocation status (anti-enumeration)
    #[error("device not found")]
    DeviceRevoked,

    #[error("UMK not found for this device")]
    UmkNotFound,

    /// Security: uses generic "UMK not found" message to prevent leaking sender device existence
    #[error("UMK not found for this device")]
    SenderNotFound,

    /// Security: uses generic "UMK not found" message to prevent leaking sender device ownership
    #[error("UMK not found for this device")]
    SenderNotOwned,

    #[error("device repository error: {0}")]
    DeviceRepository(DR),

    #[error("UMK repository error: {0}")]
    UmkRepository(UR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, UR: std::error::Error] GetDeviceUmkError<DR, UR>,
    not_found: [
        GetDeviceUmkError::DeviceNotFound,
        GetDeviceUmkError::DeviceRevoked,
        GetDeviceUmkError::UmkNotFound,
        GetDeviceUmkError::SenderNotFound,
        GetDeviceUmkError::SenderNotOwned,
    ],
    access_denied: [GetDeviceUmkError::DeviceMismatch],
);

/// Get device UMK handler
pub struct GetDeviceUmkHandler<DR: ?Sized, UR: ?Sized> {
    device_repo: Arc<DR>,
    umk_repo: Arc<UR>,
}

impl<DR, UR> GetDeviceUmkHandler<DR, UR>
where
    DR: DeviceRepository + ?Sized,
    UR: DeviceEncryptedUMKRepository + ?Sized,
{
    pub fn new(device_repo: Arc<DR>, umk_repo: Arc<UR>) -> Self {
        Self {
            device_repo,
            umk_repo,
        }
    }

    pub async fn handle(
        &self,
        query: GetDeviceUmkQuery,
    ) -> Result<GetDeviceUmkResult, GetDeviceUmkError<DR::Error, UR::Error>> {
        // 1. Verify the PoP device matches the requested device
        if query.pop_device_id != query.device_id {
            return Err(GetDeviceUmkError::DeviceMismatch);
        }

        use crate::util::device_ownership::check_active_device_ownership;

        // 2. Verify the target device exists, belongs to this user, and is not revoked
        check_active_device_ownership(&self.device_repo, query.device_id, query.user_id)
            .await
            .map_err(|e| e.map_to(
                || GetDeviceUmkError::DeviceNotFound,
                || GetDeviceUmkError::DeviceRevoked,
                GetDeviceUmkError::DeviceRepository,
            ))?;

        // 3. Find the encrypted UMK for this device
        let device_umk = self
            .umk_repo
            .find_by_user_and_device(query.user_id, query.device_id)
            .await
            .map_err(GetDeviceUmkError::UmkRepository)?
            .ok_or(GetDeviceUmkError::UmkNotFound)?;

        // 4. Find the sender device to get their public keys
        let sender_device = self
            .device_repo
            .find_by_id(device_umk.sender_device_id)
            .await
            .map_err(GetDeviceUmkError::DeviceRepository)?
            .ok_or(GetDeviceUmkError::SenderNotFound)?;

        // Verify sender device belongs to the same user
        if sender_device.user_id != query.user_id {
            return Err(GetDeviceUmkError::SenderNotOwned);
        }

        // Note: We don't check if sender device is revoked because:
        // 1. The UMK was already distributed before revocation
        // 2. The encrypted data is still valid for decryption
        // 3. The new device needs to retrieve UMK regardless of sender's current status

        Ok(GetDeviceUmkResult {
            sender_device_id: device_umk.sender_device_id,
            sender_ecdh_public_key: sender_device.ecdh_public_key,
            sender_signing_public_key: sender_device.signing_public_key,
            encrypted_umk: device_umk.encrypted_umk,
            nonce: device_umk.nonce,
        })
    }
}
