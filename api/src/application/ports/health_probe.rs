use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
}

#[async_trait]
pub trait HealthProbe: Send + Sync {
    async fn probe(&self) -> anyhow::Result<HealthStatus>;
}
