//! List pending devices query
//!
//! Returns all pending devices awaiting approval for a user.

use domain::encryption::{DeviceId, DeviceType, PendingDeviceRepository};
use domain::identity::UserId;
use std::sync::Arc;
use thiserror::Error;

/// List pending devices query
#[derive(Debug)]
pub struct ListPendingDevicesQuery {
    /// User ID
    pub user_id: UserId,
}

/// Pending device info for display
#[derive(Debug)]
pub struct PendingDeviceInfo {
    pub id: DeviceId,
    pub name: String,
    pub device_type: DeviceType,
    pub ip_address: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// List pending devices error
#[derive(Debug, Error)]
pub enum ListPendingDevicesError<PDR: std::error::Error> {
    #[error("pending device repository error: {0}")]
    PendingDeviceRepository(PDR),
}

/// List pending devices handler
pub struct ListPendingDevicesHandler<PDR> {
    pending_device_repo: Arc<PDR>,
}

impl<PDR> ListPendingDevicesHandler<PDR>
where
    PDR: PendingDeviceRepository,
{
    pub fn new(pending_device_repo: Arc<PDR>) -> Self {
        Self {
            pending_device_repo,
        }
    }

    pub async fn handle(
        &self,
        query: ListPendingDevicesQuery,
    ) -> Result<Vec<PendingDeviceInfo>, ListPendingDevicesError<PDR::Error>> {
        // Get all pending devices for the user
        let pending_devices = self
            .pending_device_repo
            .find_by_user_id(query.user_id)
            .await
            .map_err(ListPendingDevicesError::PendingDeviceRepository)?;

        // Filter out expired devices and map to info
        let now = chrono::Utc::now();
        let active_devices: Vec<PendingDeviceInfo> = pending_devices
            .into_iter()
            .filter(|d| d.expires_at > now)
            .map(|d| PendingDeviceInfo {
                id: d.id,
                name: d.name,
                device_type: d.device_type,
                ip_address: d.ip_address,
                created_at: d.created_at,
                expires_at: d.expires_at,
            })
            .collect();

        Ok(active_devices)
    }
}
