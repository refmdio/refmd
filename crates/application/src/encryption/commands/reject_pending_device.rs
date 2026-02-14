//! Reject pending device command
//!
//! Verifies ownership and deletes a pending device.

use crate::events::DeviceEventPublisher;
use domain::encryption::{DeviceId, PendingDeviceRepository};
use domain::identity::UserId;
use std::sync::Arc;
use thiserror::Error;

/// Reject pending device command
pub struct RejectPendingDeviceCommand {
    pub user_id: UserId,
    pub pending_device_id: DeviceId,
}

/// Reject pending device error
#[derive(Debug, Error)]
pub enum RejectPendingDeviceError<PDR: std::error::Error> {
    #[error("pending device not found")]
    NotFound,
    #[error("pending device does not belong to this user")]
    Forbidden,
    #[error("repository error: {0}")]
    Repository(PDR),
}

crate::types::impl_app_error!(
    [PDR: std::error::Error]
    RejectPendingDeviceError<PDR>,
    not_found: [RejectPendingDeviceError::NotFound],
    access_denied: [RejectPendingDeviceError::Forbidden],
);

/// Reject pending device handler
pub struct RejectPendingDeviceHandler<PDR: ?Sized> {
    pending_device_repo: Arc<PDR>,
    event_publisher: Arc<dyn DeviceEventPublisher>,
}

impl<PDR> RejectPendingDeviceHandler<PDR>
where
    PDR: PendingDeviceRepository + ?Sized,
{
    pub fn new(
        pending_device_repo: Arc<PDR>,
        event_publisher: Arc<dyn DeviceEventPublisher>,
    ) -> Self {
        Self {
            pending_device_repo,
            event_publisher,
        }
    }

    pub async fn handle(
        &self,
        command: RejectPendingDeviceCommand,
    ) -> Result<(), RejectPendingDeviceError<PDR::Error>> {
        let pending_device = self
            .pending_device_repo
            .find_by_id(command.pending_device_id)
            .await
            .map_err(RejectPendingDeviceError::Repository)?
            .ok_or(RejectPendingDeviceError::NotFound)?;

        if pending_device.user_id != command.user_id {
            return Err(RejectPendingDeviceError::Forbidden);
        }

        self.pending_device_repo
            .delete(command.pending_device_id)
            .await
            .map_err(RejectPendingDeviceError::Repository)?;

        // Notify the new device waiting for approval
        self.event_publisher
            .pending_removed(command.pending_device_id, command.user_id)
            .await;

        Ok(())
    }
}
