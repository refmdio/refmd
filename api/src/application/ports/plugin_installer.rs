use async_trait::async_trait;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct InstalledPlugin {
    pub id: String,
    pub version: String,
}

#[derive(thiserror::Error, Debug)]
pub enum PluginInstallError {
    #[error("invalid plugin package")]
    InvalidPackage(#[source] anyhow::Error),
    #[error("failed to persist plugin package")]
    Storage(#[source] anyhow::Error),
}

#[async_trait]
pub trait PluginInstaller: Send + Sync {
    async fn install_for_user(
        &self,
        user_id: Uuid,
        archive: &[u8],
    ) -> Result<InstalledPlugin, PluginInstallError>;
}
