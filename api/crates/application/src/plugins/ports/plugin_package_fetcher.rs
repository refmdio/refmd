use async_trait::async_trait;

use crate::core::ports::errors::PortResult;

#[async_trait]
pub trait PluginPackageFetcher: Send + Sync {
    async fn fetch(&self, url: &str, token: Option<&str>) -> PortResult<Vec<u8>>;
}
