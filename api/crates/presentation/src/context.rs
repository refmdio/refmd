use std::sync::Arc;

use futures_util::stream::BoxStream;

use application::core::ports::storage::storage_ingest_queue::StorageIngestQueue;
use application::core::services::authorization::AuthorizationServiceFacade;
use application::core::services::health::HealthServiceFacade;
use application::core::services::markdown_render::MarkdownRenderServiceFacade;
use application::core::services::metrics::MetricsRegistryFacade;
use application::documents::ports::realtime::realtime_port::RealtimeEngine;
pub use application::documents::ports::realtime::realtime_types::{
    DynRealtimeSink, DynRealtimeStream,
};
use application::documents::services::DocumentServiceFacade;
use application::documents::services::files::FileServiceFacade;
use application::documents::services::publishing::PublicServiceFacade;
use application::documents::services::sharing::ShareServiceFacade;
use application::documents::services::tagging::TagServiceFacade;
use application::git::services::GitServiceFacade;
use application::identity::services::api_tokens::ApiTokenServiceFacade;
use application::identity::services::auth::account::AccountServiceFacade;
use application::identity::services::auth::auth_service::AuthServiceFacade;
use application::identity::services::auth::external::ExternalAuthRegistryFacade;
use application::identity::services::auth::user_sessions::UserSessionServiceFacade;
use application::identity::services::user_shortcuts::UserShortcutServiceFacade;
use application::plugins::ports::plugin_event_publisher::PluginScopedEvent;
use application::plugins::ports::plugin_event_subscriber::PluginEventSubscriber;
use application::plugins::services::data::PluginDataServiceFacade;
use application::plugins::services::execution::PluginExecutionServiceFacade;
use application::plugins::services::management::PluginManagementServiceFacade;
use application::plugins::services::permissions::PluginPermissionServiceFacade;
use application::workspaces::services::WorkspaceServiceFacade;

#[derive(Debug, Clone)]
pub struct PresentationConfig {
    pub frontend_url: Option<String>,
    pub upload_max_bytes: usize,
    pub public_base_url: Option<String>,
    pub session_cookie_secure: bool,
}

#[derive(Clone)]
pub struct AppContext {
    pub cfg: PresentationConfig,
    services: Arc<AppServices>,
    metrics: Arc<dyn MetricsRegistryFacade>,
}

#[derive(Clone)]
pub struct AppServices {
    core: CoreServices,
    documents: DocumentServices,
    git: GitServices,
    identity: IdentityServices,
    plugins: PluginServices,
    workspaces: WorkspaceServices,
}

#[derive(Clone)]
struct CoreServices {
    authorization: Arc<dyn AuthorizationServiceFacade>,
    markdown_render_service: Arc<dyn MarkdownRenderServiceFacade>,
    storage_ingest_queue: Arc<dyn StorageIngestQueue>,
    health_service: Arc<dyn HealthServiceFacade>,
}

#[derive(Clone)]
struct DocumentServices {
    document_service: Arc<dyn DocumentServiceFacade>,
    share_service: Arc<dyn ShareServiceFacade>,
    file_service: Arc<dyn FileServiceFacade>,
    public_service: Arc<dyn PublicServiceFacade>,
    tag_service: Arc<dyn TagServiceFacade>,
    realtime_engine: Arc<dyn RealtimeEngine>,
}

#[derive(Clone)]
struct GitServices {
    git_service: Arc<dyn GitServiceFacade>,
}

#[derive(Clone)]
struct IdentityServices {
    api_token_service: Arc<dyn ApiTokenServiceFacade>,
    user_shortcut_service: Arc<dyn UserShortcutServiceFacade>,
    account_service: Arc<dyn AccountServiceFacade>,
    auth_service: Arc<dyn AuthServiceFacade>,
    session_service: Arc<dyn UserSessionServiceFacade>,
    external_auth: Arc<dyn ExternalAuthRegistryFacade>,
}

#[derive(Clone)]
struct PluginServices {
    plugin_execution_service: Arc<dyn PluginExecutionServiceFacade>,
    plugin_management_service: Arc<dyn PluginManagementServiceFacade>,
    plugin_permission_service: Arc<dyn PluginPermissionServiceFacade>,
    plugin_data_service: Arc<dyn PluginDataServiceFacade>,
    plugin_event_subscriber: Arc<dyn PluginEventSubscriber>,
}

#[derive(Clone)]
struct WorkspaceServices {
    workspace_service: Arc<dyn WorkspaceServiceFacade>,
}

impl AppServices {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization: Arc<dyn AuthorizationServiceFacade>,
        document_service: Arc<dyn DocumentServiceFacade>,
        share_service: Arc<dyn ShareServiceFacade>,
        file_service: Arc<dyn FileServiceFacade>,
        public_service: Arc<dyn PublicServiceFacade>,
        tag_service: Arc<dyn TagServiceFacade>,
        api_token_service: Arc<dyn ApiTokenServiceFacade>,
        user_shortcut_service: Arc<dyn UserShortcutServiceFacade>,
        git_service: Arc<dyn GitServiceFacade>,
        markdown_render_service: Arc<dyn MarkdownRenderServiceFacade>,
        workspace_service: Arc<dyn WorkspaceServiceFacade>,
        plugin_execution_service: Arc<dyn PluginExecutionServiceFacade>,
        plugin_management_service: Arc<dyn PluginManagementServiceFacade>,
        plugin_permission_service: Arc<dyn PluginPermissionServiceFacade>,
        plugin_data_service: Arc<dyn PluginDataServiceFacade>,
        plugin_event_subscriber: Arc<dyn PluginEventSubscriber>,
        health_service: Arc<dyn HealthServiceFacade>,
        account_service: Arc<dyn AccountServiceFacade>,
        auth_service: Arc<dyn AuthServiceFacade>,
        session_service: Arc<dyn UserSessionServiceFacade>,
        realtime_engine: Arc<dyn RealtimeEngine>,
        storage_ingest_queue: Arc<dyn StorageIngestQueue>,
        external_auth: Arc<dyn ExternalAuthRegistryFacade>,
    ) -> Self {
        Self {
            core: CoreServices {
                authorization,
                markdown_render_service,
                storage_ingest_queue,
                health_service,
            },
            documents: DocumentServices {
                document_service,
                share_service,
                file_service,
                public_service,
                tag_service,
                realtime_engine,
            },
            git: GitServices { git_service },
            identity: IdentityServices {
                api_token_service,
                user_shortcut_service,
                account_service,
                auth_service,
                session_service,
                external_auth,
            },
            plugins: PluginServices {
                plugin_execution_service,
                plugin_management_service,
                plugin_permission_service,
                plugin_data_service,
                plugin_event_subscriber,
            },
            workspaces: WorkspaceServices { workspace_service },
        }
    }
}

impl AppContext {
    pub fn new(
        cfg: PresentationConfig,
        services: AppServices,
        metrics: Arc<dyn MetricsRegistryFacade>,
    ) -> Self {
        Self {
            cfg,
            services: Arc::new(services),
            metrics,
        }
    }

    pub fn authorization(&self) -> Arc<dyn AuthorizationServiceFacade> {
        self.services.core.authorization.clone()
    }

    pub fn document_service(&self) -> Arc<dyn DocumentServiceFacade> {
        self.services.documents.document_service.clone()
    }

    pub fn share_service(&self) -> Arc<dyn ShareServiceFacade> {
        self.services.documents.share_service.clone()
    }

    pub fn file_service(&self) -> Arc<dyn FileServiceFacade> {
        self.services.documents.file_service.clone()
    }

    pub fn public_service(&self) -> Arc<dyn PublicServiceFacade> {
        self.services.documents.public_service.clone()
    }

    pub fn tag_service(&self) -> Arc<dyn TagServiceFacade> {
        self.services.documents.tag_service.clone()
    }

    pub fn user_shortcut_service(&self) -> Arc<dyn UserShortcutServiceFacade> {
        self.services.identity.user_shortcut_service.clone()
    }

    pub fn git_service(&self) -> Arc<dyn GitServiceFacade> {
        self.services.git.git_service.clone()
    }

    pub fn markdown_renderer(&self) -> Arc<dyn MarkdownRenderServiceFacade> {
        self.services.core.markdown_render_service.clone()
    }

    pub fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.services.workspaces.workspace_service.clone()
    }

    pub fn storage_ingest_queue(&self) -> Arc<dyn StorageIngestQueue> {
        self.services.core.storage_ingest_queue.clone()
    }

    pub fn plugin_execution_service(&self) -> Arc<dyn PluginExecutionServiceFacade> {
        self.services.plugins.plugin_execution_service.clone()
    }

    pub fn plugin_management(&self) -> Arc<dyn PluginManagementServiceFacade> {
        self.services.plugins.plugin_management_service.clone()
    }

    pub fn plugin_permissions(&self) -> Arc<dyn PluginPermissionServiceFacade> {
        self.services.plugins.plugin_permission_service.clone()
    }

    pub fn plugin_data_service(&self) -> Arc<dyn PluginDataServiceFacade> {
        self.services.plugins.plugin_data_service.clone()
    }

    pub fn health_service(&self) -> Arc<dyn HealthServiceFacade> {
        self.services.core.health_service.clone()
    }

    pub fn account_service(&self) -> Arc<dyn AccountServiceFacade> {
        self.services.identity.account_service.clone()
    }

    pub fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.services.identity.auth_service.clone()
    }

    pub fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.services.identity.session_service.clone()
    }

    pub fn external_auth(&self) -> Arc<dyn ExternalAuthRegistryFacade> {
        self.services.identity.external_auth.clone()
    }

    pub fn metrics(&self) -> Arc<dyn MetricsRegistryFacade> {
        self.metrics.clone()
    }

    pub async fn subscribe_plugin_events(
        &self,
    ) -> anyhow::Result<BoxStream<'static, PluginScopedEvent>> {
        self.services
            .plugins
            .plugin_event_subscriber
            .subscribe()
            .await
    }

    pub fn api_token_service(&self) -> Arc<dyn ApiTokenServiceFacade> {
        self.services.identity.api_token_service.clone()
    }

    pub async fn subscribe_realtime(
        &self,
        doc_id: &str,
        sink: DynRealtimeSink,
        stream: DynRealtimeStream,
        can_edit: bool,
    ) -> anyhow::Result<()> {
        self.services
            .documents
            .realtime_engine
            .subscribe(doc_id, sink, stream, can_edit)
            .await
    }
}
