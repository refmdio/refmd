use std::sync::Arc;

use crate::core::ports::health_probe::{HealthProbe, HealthStatus};
use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverallHealth {
    Ok,
    Degraded,
}

pub struct HealthService {
    probe: Arc<dyn HealthProbe>,
}

#[async_trait]
pub trait HealthServiceFacade: Send + Sync {
    async fn status(&self) -> anyhow::Result<OverallHealth>;
}

#[async_trait]
impl HealthServiceFacade for HealthService {
    async fn status(&self) -> anyhow::Result<OverallHealth> {
        self.status().await
    }
}

impl HealthService {
    pub fn new(probe: Arc<dyn HealthProbe>) -> Self {
        Self { probe }
    }

    pub async fn status(&self) -> anyhow::Result<OverallHealth> {
        match self.probe.probe().await? {
            HealthStatus::Healthy => Ok(OverallHealth::Ok),
            HealthStatus::Degraded => Ok(OverallHealth::Degraded),
        }
    }
}
