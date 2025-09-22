use async_trait::async_trait;

use crate::application::ports::plugin_package_fetcher::PluginPackageFetcher;

pub struct ReqwestPluginPackageFetcher {
    client: reqwest::Client,
}

impl ReqwestPluginPackageFetcher {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl PluginPackageFetcher for ReqwestPluginPackageFetcher {
    async fn fetch(&self, url: &str, token: Option<&str>) -> anyhow::Result<Vec<u8>> {
        let mut req = self.client.get(url);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("request failed: {e}"))?;
        if !resp.status().is_success() {
            anyhow::bail!("upstream returned status {}", resp.status());
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("failed to read body: {e}"))?;
        Ok(bytes.to_vec())
    }
}
