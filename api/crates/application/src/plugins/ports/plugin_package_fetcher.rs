use async_trait::async_trait;

#[async_trait]
pub trait PluginPackageFetcher: Send + Sync {
    async fn fetch(&self, url: &str, token: Option<&str>) -> anyhow::Result<Vec<u8>>;
}
