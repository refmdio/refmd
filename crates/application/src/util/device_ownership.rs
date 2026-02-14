//! Shared device ownership verification utility
//!
//! Checks whether a device (pending or active) belongs to a given user.
//! Used by trust-transfer handlers (`request_nonce`, `submit_state`)
//! and active-device-only checks (PoP, UMK distribution).

use domain::encryption::{Device, DeviceId, DeviceRepository, PendingDeviceRepository};
use domain::identity::UserId;
use std::sync::Arc;

/// Result of a device ownership check.
pub enum DeviceOwnership {
    /// Device is a pending device owned by the user.
    Pending,
    /// Device is an active (non-revoked) device owned by the user.
    Active,
}

/// Error from device ownership check, preserving the original repository error types.
pub enum DeviceOwnershipError<DR: std::error::Error, PDR: std::error::Error> {
    /// Device not found or does not belong to user.
    NotFound,
    /// Pending device repository error.
    PendingDeviceRepository(PDR),
    /// Device repository error.
    DeviceRepository(DR),
}

/// Verify that a device (pending or active) belongs to the given user and is not revoked.
///
/// Checks pending devices first, then active devices.
pub async fn check_device_ownership<DR, PDR>(
    device_repo: &Arc<DR>,
    pending_device_repo: &Arc<PDR>,
    device_id: DeviceId,
    user_id: UserId,
) -> Result<DeviceOwnership, DeviceOwnershipError<DR::Error, PDR::Error>>
where
    DR: DeviceRepository + ?Sized,
    PDR: PendingDeviceRepository + ?Sized,
{
    // Check pending devices first
    match pending_device_repo.find_by_id(device_id).await {
        Ok(Some(pending)) if pending.user_id == user_id && !pending.is_expired() => {
            return Ok(DeviceOwnership::Pending);
        }
        Ok(_) => {} // Not found or wrong user — fall through to active check
        Err(e) => {
            tracing::error!("Failed to check pending device: {}", e);
            return Err(DeviceOwnershipError::PendingDeviceRepository(e));
        }
    }

    // Check active devices
    match device_repo.find_by_id(device_id).await {
        Ok(Some(device)) if device.user_id == user_id && !device.is_revoked() => {
            Ok(DeviceOwnership::Active)
        }
        Ok(_) => Err(DeviceOwnershipError::NotFound),
        Err(e) => {
            tracing::error!("Failed to check device: {}", e);
            Err(DeviceOwnershipError::DeviceRepository(e))
        }
    }
}

/// Result of verifying a session's device binding against active devices.
pub struct SessionDeviceVerification {
    /// Whether the session's device_id matches an active device of this user.
    pub device_verified: bool,
    /// The device_id if verified, None otherwise.
    pub verified_device_id: Option<DeviceId>,
    /// Whether the user has any active devices.
    pub has_devices: bool,
}

/// Verify a session's device binding against the user's active devices.
///
/// Used by login and /auth/me to check if the session's device_id
/// refers to a valid, active device owned by this user.
pub async fn verify_session_device<DR>(
    device_repo: &Arc<DR>,
    user_id: UserId,
    session_device_id: Option<DeviceId>,
) -> Result<SessionDeviceVerification, DR::Error>
where
    DR: DeviceRepository + ?Sized,
{
    let devices = device_repo.find_active_by_user_id(user_id).await?;
    let has_devices = !devices.is_empty();

    let (device_verified, verified_device_id) = if let Some(device_id) = session_device_id {
        let device_valid = devices.iter().any(|d| d.id == device_id);
        (
            device_valid,
            if device_valid { Some(device_id) } else { None },
        )
    } else {
        (false, None)
    };

    Ok(SessionDeviceVerification {
        device_verified,
        verified_device_id,
        has_devices,
    })
}

/// Error from active device ownership check.
pub enum ActiveDeviceOwnershipError<E: std::error::Error> {
    /// Device not found or does not belong to user.
    NotFound,
    /// Device has been revoked.
    Revoked,
    /// Device repository error.
    DeviceRepository(E),
}

impl<E: std::error::Error> ActiveDeviceOwnershipError<E> {
    /// Map each variant to a target type via closures.
    pub fn map_to<T>(
        self,
        not_found: impl FnOnce() -> T,
        revoked: impl FnOnce() -> T,
        repo_error: impl FnOnce(E) -> T,
    ) -> T {
        match self {
            Self::NotFound => not_found(),
            Self::Revoked => revoked(),
            Self::DeviceRepository(e) => repo_error(e),
        }
    }
}

/// Error from PoP sender + device ownership verification.
pub enum PopSenderDeviceError<E: std::error::Error> {
    /// `sender_device_id` does not match `authenticated_device_id`.
    SenderMismatch,
    /// Target device not found / not owned / revoked.
    Target(ActiveDeviceOwnershipError<E>),
    /// Sender device not found / not owned / revoked.
    Sender(ActiveDeviceOwnershipError<E>),
}

impl<E: std::error::Error> PopSenderDeviceError<E> {
    /// Map each variant to a target type via closures.
    #[allow(clippy::too_many_arguments)]
    pub fn map_to<T>(
        self,
        sender_mismatch: impl FnOnce() -> T,
        target_not_found: impl FnOnce() -> T,
        target_revoked: impl FnOnce() -> T,
        target_repo: impl FnOnce(E) -> T,
        sender_not_found: impl FnOnce() -> T,
        sender_revoked: impl FnOnce() -> T,
        sender_repo: impl FnOnce(E) -> T,
    ) -> T {
        match self {
            Self::SenderMismatch => sender_mismatch(),
            Self::Target(ae) => ae.map_to(target_not_found, target_revoked, target_repo),
            Self::Sender(ae) => ae.map_to(sender_not_found, sender_revoked, sender_repo),
        }
    }
}

/// Verify PoP sender binding and ownership of both target and sender devices.
///
/// Common guard used by handlers that accept a `sender_device_id` alongside
/// a PoP-authenticated `authenticated_device_id` and a separate
/// `target_device_id`.
///
/// 1. Ensures `sender_device_id == authenticated_device_id`.
/// 2. Verifies target device is active + owned by `user_id`.
/// 3. Verifies sender device is active + owned by `user_id`.
pub async fn verify_pop_sender_and_devices<DR>(
    device_repo: &Arc<DR>,
    user_id: UserId,
    target_device_id: DeviceId,
    sender_device_id: DeviceId,
    authenticated_device_id: DeviceId,
) -> Result<(Device, Device), PopSenderDeviceError<DR::Error>>
where
    DR: DeviceRepository + ?Sized,
{
    if sender_device_id != authenticated_device_id {
        return Err(PopSenderDeviceError::SenderMismatch);
    }

    let target = check_active_device_ownership(device_repo, target_device_id, user_id)
        .await
        .map_err(PopSenderDeviceError::Target)?;

    let sender = check_active_device_ownership(device_repo, sender_device_id, user_id)
        .await
        .map_err(PopSenderDeviceError::Sender)?;

    Ok((target, sender))
}

/// Verify that an active (non-revoked) device belongs to the given user.
///
/// Returns the [`Device`] on success for callers that need it.
pub async fn check_active_device_ownership<DR>(
    device_repo: &Arc<DR>,
    device_id: DeviceId,
    user_id: UserId,
) -> Result<Device, ActiveDeviceOwnershipError<DR::Error>>
where
    DR: DeviceRepository + ?Sized,
{
    let device = device_repo
        .find_by_id(device_id)
        .await
        .map_err(ActiveDeviceOwnershipError::DeviceRepository)?
        .ok_or(ActiveDeviceOwnershipError::NotFound)?;

    if device.user_id != user_id {
        return Err(ActiveDeviceOwnershipError::NotFound);
    }

    if device.is_revoked() {
        return Err(ActiveDeviceOwnershipError::Revoked);
    }

    Ok(device)
}
