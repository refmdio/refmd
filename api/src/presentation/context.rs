use std::sync::Arc;

use futures_util::stream::BoxStream;

use crate::application::ports::plugin_event_publisher::PluginScopedEvent;
use crate::application::ports::plugin_event_subscriber::PluginEventSubscriber;
use crate::application::ports::realtime_port::RealtimeEngine;
pub use crate::application::ports::realtime_types::{DynRealtimeSink, DynRealtimeStream};
use crate::application::services::api_tokens::ApiTokenService;
use crate::application::services::auth::account::AccountService;
use crate::application::services::auth::service::AuthService;
use crate::application::services::authorization::AuthorizationService;
use crate::application::services::documents::DocumentService;
use crate::application::services::files::FileService;
use crate::application::services::git::GitService;
use crate::application::services::health::HealthService;
use crate::application::services::markdown_render::MarkdownRenderService;
use crate::application::services::plugins::data::PluginDataService;
use crate::application::services::plugins::execution::PluginExecutionService;
use crate::application::services::plugins::management::PluginManagementService;
use crate::application::services::plugins::permissions::PluginPermissionService;
use crate::application::services::public::PublicService;
use crate::application::services::shares::ShareService;
use crate::application::services::tags::TagService;
use crate::application::services::user_shortcuts::UserShortcutService;

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
}

#[derive(Clone)]
pub struct AppServices {
    authorization: Arc<AuthorizationService>,
    document_service: Arc<DocumentService>,
    share_service: Arc<ShareService>,
    file_service: Arc<FileService>,
    public_service: Arc<PublicService>,
    tag_service: Arc<TagService>,
    api_token_service: Arc<ApiTokenService>,
    user_shortcut_service: Arc<UserShortcutService>,
    git_service: Arc<GitService>,
    markdown_render_service: Arc<MarkdownRenderService>,
    plugin_execution_service: Arc<PluginExecutionService>,
    plugin_management_service: Arc<PluginManagementService>,
    plugin_permission_service: Arc<PluginPermissionService>,
    plugin_data_service: Arc<PluginDataService>,
    plugin_event_subscriber: Arc<dyn PluginEventSubscriber>,
    health_service: Arc<HealthService>,
    account_service: Arc<AccountService>,
    auth_service: Arc<AuthService>,
    realtime_engine: Arc<dyn RealtimeEngine>,
}

impl AppServices {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization: Arc<AuthorizationService>,
        document_service: Arc<DocumentService>,
        share_service: Arc<ShareService>,
        file_service: Arc<FileService>,
        public_service: Arc<PublicService>,
        tag_service: Arc<TagService>,
        api_token_service: Arc<ApiTokenService>,
        user_shortcut_service: Arc<UserShortcutService>,
        git_service: Arc<GitService>,
        markdown_render_service: Arc<MarkdownRenderService>,
        plugin_execution_service: Arc<PluginExecutionService>,
        plugin_management_service: Arc<PluginManagementService>,
        plugin_permission_service: Arc<PluginPermissionService>,
        plugin_data_service: Arc<PluginDataService>,
        plugin_event_subscriber: Arc<dyn PluginEventSubscriber>,
        health_service: Arc<HealthService>,
        account_service: Arc<AccountService>,
        auth_service: Arc<AuthService>,
        realtime_engine: Arc<dyn RealtimeEngine>,
    ) -> Self {
        Self {
            authorization,
            document_service,
            share_service,
            file_service,
            public_service,
            tag_service,
            api_token_service,
            user_shortcut_service,
            git_service,
            markdown_render_service,
            plugin_execution_service,
            plugin_management_service,
            plugin_permission_service,
            plugin_data_service,
            plugin_event_subscriber,
            health_service,
            account_service,
            auth_service,
            realtime_engine,
        }
    }
}

impl AppContext {
    pub fn new(cfg: PresentationConfig, services: AppServices) -> Self {
        Self {
            cfg,
            services: Arc::new(services),
        }
    }

    pub fn authorization(&self) -> Arc<AuthorizationService> {
        self.services.authorization.clone()
    }

    pub fn document_service(&self) -> Arc<DocumentService> {
        self.services.document_service.clone()
    }

    pub fn share_service(&self) -> Arc<ShareService> {
        self.services.share_service.clone()
    }

    pub fn file_service(&self) -> Arc<FileService> {
        self.services.file_service.clone()
    }

    pub fn public_service(&self) -> Arc<PublicService> {
        self.services.public_service.clone()
    }

    pub fn tag_service(&self) -> Arc<TagService> {
        self.services.tag_service.clone()
    }

    pub fn user_shortcut_service(&self) -> Arc<UserShortcutService> {
        self.services.user_shortcut_service.clone()
    }

    pub fn git_service(&self) -> Arc<GitService> {
        self.services.git_service.clone()
    }

    pub fn markdown_renderer(&self) -> Arc<MarkdownRenderService> {
        self.services.markdown_render_service.clone()
    }

    pub fn plugin_execution_service(&self) -> Arc<PluginExecutionService> {
        self.services.plugin_execution_service.clone()
    }

    pub fn plugin_management(&self) -> Arc<PluginManagementService> {
        self.services.plugin_management_service.clone()
    }

    pub fn plugin_permissions(&self) -> Arc<PluginPermissionService> {
        self.services.plugin_permission_service.clone()
    }

    pub fn plugin_data_service(&self) -> Arc<PluginDataService> {
        self.services.plugin_data_service.clone()
    }

    pub fn health_service(&self) -> Arc<HealthService> {
        self.services.health_service.clone()
    }

    pub fn account_service(&self) -> Arc<AccountService> {
        self.services.account_service.clone()
    }

    pub fn auth_service(&self) -> Arc<AuthService> {
        self.services.auth_service.clone()
    }

    pub async fn subscribe_plugin_events(
        &self,
    ) -> anyhow::Result<BoxStream<'static, PluginScopedEvent>> {
        self.services.plugin_event_subscriber.subscribe().await
    }

    pub fn api_token_service(&self) -> Arc<ApiTokenService> {
        self.services.api_token_service.clone()
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
