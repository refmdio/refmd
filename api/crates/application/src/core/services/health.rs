use std::sync::Arc;

use crate::core::ports::health_probe::{HealthProbe, HealthStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverallHealth {
    Ok,
    Degraded,
}

pub struct HealthService {
    probe: Arc<dyn HealthProbe>,
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
