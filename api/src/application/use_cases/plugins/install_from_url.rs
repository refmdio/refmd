use crate::application::ports::plugin_event_publisher::{PluginEventPublisher, PluginScopedEvent};
use crate::application::ports::plugin_installation_repository::PluginInstallationRepository;
use crate::application::ports::plugin_installer::{
    InstalledPlugin, PluginInstallError, PluginInstaller,
};
use crate::application::ports::plugin_package_fetcher::PluginPackageFetcher;
use uuid::Uuid;

#[derive(thiserror::Error, Debug)]
pub enum InstallPluginError {
    #[error("failed to download plugin package")]
    Download(#[source] anyhow::Error),
    #[error("failed to install plugin package")]
    Install(#[source] PluginInstallError),
    #[error("failed to persist plugin installation")]
    Persist(#[source] anyhow::Error),
    #[error("failed to publish plugin event")]
    Event(#[source] anyhow::Error),
}

pub struct InstallPluginFromUrl<'a, F, I, E, R>
where
    F: PluginPackageFetcher + ?Sized,
    I: PluginInstaller + ?Sized,
    E: PluginEventPublisher + ?Sized,
    R: PluginInstallationRepository + ?Sized,
{
    pub fetcher: &'a F,
    pub installer: &'a I,
    pub events: &'a E,
    pub installations: &'a R,
}

impl<'a, F, I, E, R> InstallPluginFromUrl<'a, F, I, E, R>
where
    F: PluginPackageFetcher + ?Sized,
    I: PluginInstaller + ?Sized,
    E: PluginEventPublisher + ?Sized,
    R: PluginInstallationRepository + ?Sized,
{
    pub async fn execute(
        &self,
        user_id: Uuid,
        url: &str,
        token: Option<&str>,
    ) -> Result<InstalledPlugin, InstallPluginError> {
        let bytes = self
            .fetcher
            .fetch(url, token)
            .await
            .map_err(InstallPluginError::Download)?;
        let installed = self
            .installer
            .install_for_user(user_id, &bytes)
            .await
            .map_err(InstallPluginError::Install)?;

        self.installations
            .upsert(
                user_id,
                &installed.id,
                &installed.version,
                "user",
                Some(url),
                "enabled",
            )
            .await
            .map_err(InstallPluginError::Persist)?;

        let event = PluginScopedEvent {
            user_id: Some(user_id),
            payload: serde_json::json!({
                "event": "installed",
                "id": installed.id,
                "version": installed.version,
            }),
        };
        self.events
            .publish(&event)
            .await
            .map_err(InstallPluginError::Event)?;
        Ok(installed)
    }
}
