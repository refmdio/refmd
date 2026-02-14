//! List devices query
//!
//! Lists all active (non-revoked) devices for a user.

use crate::dto::DeviceDto;
use domain::encryption::DeviceRepository;
use domain::identity::UserId;
use std::sync::Arc;
use thiserror::Error;

/// List devices query
#[derive(Debug)]
pub struct ListDevicesQuery {
    pub user_id: UserId,
}

/// List devices result
#[derive(Debug)]
pub struct ListDevicesResult {
    pub devices: Vec<DeviceDto>,
}

/// List devices error
#[derive(Debug, Error)]
pub enum ListDevicesError<DR: std::error::Error> {
    #[error("device repository error: {0}")]
    DeviceRepository(DR),
}

/// List devices handler
pub struct ListDevicesHandler<DR: ?Sized> {
    device_repo: Arc<DR>,
}

impl<DR> ListDevicesHandler<DR>
where
    DR: DeviceRepository + ?Sized,
{
    pub fn new(device_repo: Arc<DR>) -> Self {
        Self { device_repo }
    }

    pub async fn handle(
        &self,
        query: ListDevicesQuery,
    ) -> Result<ListDevicesResult, ListDevicesError<DR::Error>> {
        let devices = self
            .device_repo
            .find_active_by_user_id(query.user_id)
            .await
            .map_err(ListDevicesError::DeviceRepository)?;

        Ok(ListDevicesResult { devices: devices.into_iter().map(Into::into).collect() })
    }
}
