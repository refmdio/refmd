use std::sync::Arc;

use crate::application::ports::access_repository::AccessRepository;
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_storage::GitStorage;
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::gitignore_port::GitignorePort;
use crate::application::ports::plugin_asset_store::PluginAssetStore;
use crate::application::ports::plugin_event_publisher::{PluginEventPublisher, PluginScopedEvent};
use crate::application::ports::plugin_installation_repository::PluginInstallationRepository;
use crate::application::ports::plugin_installer::PluginInstaller;
use crate::application::ports::plugin_package_fetcher::PluginPackageFetcher;
use crate::application::ports::plugin_repository::PluginRepository;
use crate::application::ports::plugin_runtime::PluginRuntime;
use crate::application::ports::public_repository::PublicRepository;
use crate::application::ports::realtime_port::RealtimeEngine;
pub use crate::application::ports::realtime_types::{DynRealtimeSink, DynRealtimeStream};
use crate::application::ports::share_access_port::ShareAccessPort;
use crate::application::ports::shares_repository::SharesRepository;
use crate::application::ports::storage_port::StoragePort;
use crate::application::ports::tag_repository::TagRepository;
use crate::application::ports::user_repository::UserRepository;
use crate::bootstrap::config::Config;
use futures_util::{StreamExt, stream::BoxStream};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

#[derive(Clone)]
pub struct AppContext {
    pub cfg: Config,
    services: Arc<AppServices>,
}

#[derive(Clone)]
pub struct AppServices {
    document_repo: Arc<dyn DocumentRepository>,
    shares_repo: Arc<dyn SharesRepository>,
    share_access_port: Arc<dyn ShareAccessPort>,
    access_repo: Arc<dyn AccessRepository>,
    files_repo: Arc<dyn FilesRepository>,
    public_repo: Arc<dyn PublicRepository>,
    user_repo: Arc<dyn UserRepository>,
    tag_repo: Arc<dyn TagRepository>,
    git_repo: Arc<dyn GitRepository>,
    git_storage: Arc<dyn GitStorage>,
    gitignore_port: Arc<dyn GitignorePort>,
    git_workspace: Arc<dyn GitWorkspacePort>,
    storage_port: Arc<dyn StoragePort>,
    realtime_engine: Arc<dyn RealtimeEngine>,
    plugin_repo: Arc<dyn PluginRepository>,
    plugin_installations: Arc<dyn PluginInstallationRepository>,
    plugin_runtime: Arc<dyn PluginRuntime>,
    plugin_installer: Arc<dyn PluginInstaller>,
    plugin_fetcher: Arc<dyn PluginPackageFetcher>,
    plugin_events: broadcast::Sender<PluginScopedEvent>,
    plugin_event_publisher: Arc<dyn PluginEventPublisher>,
    plugin_assets: Arc<dyn PluginAssetStore>,
}

impl AppServices {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        document_repo: Arc<dyn DocumentRepository>,
        shares_repo: Arc<dyn SharesRepository>,
        share_access_port: Arc<dyn ShareAccessPort>,
        access_repo: Arc<dyn AccessRepository>,
        files_repo: Arc<dyn FilesRepository>,
        public_repo: Arc<dyn PublicRepository>,
        user_repo: Arc<dyn UserRepository>,
        tag_repo: Arc<dyn TagRepository>,
        git_repo: Arc<dyn GitRepository>,
        git_storage: Arc<dyn GitStorage>,
        gitignore_port: Arc<dyn GitignorePort>,
        git_workspace: Arc<dyn GitWorkspacePort>,
        storage_port: Arc<dyn StoragePort>,
        realtime_engine: Arc<dyn RealtimeEngine>,
        plugin_repo: Arc<dyn PluginRepository>,
        plugin_installations: Arc<dyn PluginInstallationRepository>,
        plugin_runtime: Arc<dyn PluginRuntime>,
        plugin_installer: Arc<dyn PluginInstaller>,
        plugin_fetcher: Arc<dyn PluginPackageFetcher>,
        plugin_events: broadcast::Sender<PluginScopedEvent>,
        plugin_event_publisher: Arc<dyn PluginEventPublisher>,
        plugin_assets: Arc<dyn PluginAssetStore>,
    ) -> Self {
        Self {
            document_repo,
            shares_repo,
            share_access_port,
            access_repo,
            files_repo,
            public_repo,
            user_repo,
            tag_repo,
            git_repo,
            git_storage,
            gitignore_port,
            git_workspace,
            storage_port,
            realtime_engine,
            plugin_repo,
            plugin_installations,
            plugin_runtime,
            plugin_installer,
            plugin_fetcher,
            plugin_events,
            plugin_event_publisher,
            plugin_assets,
        }
    }
}

impl AppContext {
    pub fn new(cfg: Config, services: AppServices) -> Self {
        Self {
            cfg,
            services: Arc::new(services),
        }
    }

    pub fn document_repo(&self) -> Arc<dyn DocumentRepository> {
        self.services.document_repo.clone()
    }

    pub fn shares_repo(&self) -> Arc<dyn SharesRepository> {
        self.services.shares_repo.clone()
    }

    pub fn share_access_port(&self) -> Arc<dyn ShareAccessPort> {
        self.services.share_access_port.clone()
    }

    pub fn access_repo(&self) -> Arc<dyn AccessRepository> {
        self.services.access_repo.clone()
    }

    pub fn files_repo(&self) -> Arc<dyn FilesRepository> {
        self.services.files_repo.clone()
    }

    pub fn public_repo(&self) -> Arc<dyn PublicRepository> {
        self.services.public_repo.clone()
    }

    pub fn user_repo(&self) -> Arc<dyn UserRepository> {
        self.services.user_repo.clone()
    }

    pub fn tag_repo(&self) -> Arc<dyn TagRepository> {
        self.services.tag_repo.clone()
    }

    pub fn git_repo(&self) -> Arc<dyn GitRepository> {
        self.services.git_repo.clone()
    }

    pub fn git_storage(&self) -> Arc<dyn GitStorage> {
        self.services.git_storage.clone()
    }

    pub fn gitignore_port(&self) -> Arc<dyn GitignorePort> {
        self.services.gitignore_port.clone()
    }

    pub fn git_workspace(&self) -> Arc<dyn GitWorkspacePort> {
        self.services.git_workspace.clone()
    }

    pub fn storage_port(&self) -> Arc<dyn StoragePort> {
        self.services.storage_port.clone()
    }

    pub fn realtime_engine(&self) -> Arc<dyn RealtimeEngine> {
        self.services.realtime_engine.clone()
    }

    pub fn plugin_repo(&self) -> Arc<dyn PluginRepository> {
        self.services.plugin_repo.clone()
    }

    pub fn plugin_installations(&self) -> Arc<dyn PluginInstallationRepository> {
        self.services.plugin_installations.clone()
    }

    pub fn plugin_runtime(&self) -> Arc<dyn PluginRuntime> {
        self.services.plugin_runtime.clone()
    }

    pub fn plugin_installer(&self) -> Arc<dyn PluginInstaller> {
        self.services.plugin_installer.clone()
    }

    pub fn plugin_fetcher(&self) -> Arc<dyn PluginPackageFetcher> {
        self.services.plugin_fetcher.clone()
    }

    pub fn plugin_event_publisher(&self) -> Arc<dyn PluginEventPublisher> {
        self.services.plugin_event_publisher.clone()
    }

    pub fn plugin_assets(&self) -> Arc<dyn PluginAssetStore> {
        self.services.plugin_assets.clone()
    }

    pub fn subscribe_plugin_events(&self) -> BoxStream<'static, PluginScopedEvent> {
        BroadcastStream::new(self.services.plugin_events.subscribe())
            .filter_map(|evt| async move { evt.ok() })
            .boxed()
    }

    pub async fn subscribe_realtime(
        &self,
        doc_id: &str,
        sink: DynRealtimeSink,
        stream: DynRealtimeStream,
        can_edit: bool,
    ) -> anyhow::Result<()> {
        self.services
            .realtime_engine
            .subscribe(doc_id, sink, stream, can_edit)
            .await
    }
}
