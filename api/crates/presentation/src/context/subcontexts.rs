use super::*;
use application::documents::services::keys::DocumentKeysServiceFacade;

#[derive(Clone)]
pub struct CoreContext {
    pub cfg: PresentationConfig,
    markdown_render_service: Arc<dyn MarkdownRenderServiceFacade>,
    storage_ingest_enqueuer: Arc<dyn StorageIngestEnqueueServiceFacade>,
    health_service: Arc<dyn HealthServiceFacade>,
    metrics: Arc<dyn MetricsRegistryFacade>,
    auth_service: Arc<dyn AuthServiceFacade>,
    session_service: Arc<dyn UserSessionServiceFacade>,
    workspace_service: Arc<dyn WorkspaceServiceFacade>,
    share_service: Arc<dyn ShareServiceFacade>,
}

impl CoreContext {
    pub fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    pub fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }

    pub fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }

    pub fn share_service(&self) -> Arc<dyn ShareServiceFacade> {
        self.share_service.clone()
    }

    pub fn markdown_renderer(&self) -> Arc<dyn MarkdownRenderServiceFacade> {
        self.markdown_render_service.clone()
    }

    pub fn storage_ingest_enqueuer(&self) -> Arc<dyn StorageIngestEnqueueServiceFacade> {
        self.storage_ingest_enqueuer.clone()
    }

    pub fn health_service(&self) -> Arc<dyn HealthServiceFacade> {
        self.health_service.clone()
    }

    pub fn metrics(&self) -> Arc<dyn MetricsRegistryFacade> {
        self.metrics.clone()
    }
}

impl HasAuthServices for CoreContext {
    fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }
}

impl HasWorkspaceService for CoreContext {
    fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }
}

impl HasShareService for CoreContext {
    fn share_service(&self) -> Arc<dyn ShareServiceFacade> {
        self.share_service.clone()
    }
}

impl FromRef<AppContext> for CoreContext {
    fn from_ref(ctx: &AppContext) -> Self {
        Self {
            cfg: ctx.cfg.clone(),
            markdown_render_service: ctx.markdown_renderer(),
            storage_ingest_enqueuer: ctx.storage_ingest_enqueuer(),
            health_service: ctx.health_service(),
            metrics: ctx.metrics(),
            auth_service: ctx.auth_service(),
            session_service: ctx.session_service(),
            workspace_service: ctx.workspace_service(),
            share_service: ctx.share_service(),
        }
    }
}

#[derive(Clone)]
pub struct DocumentsContext {
    pub cfg: PresentationConfig,
    authorization: Arc<dyn AuthorizationServiceFacade>,
    document_service: Arc<dyn DocumentServiceFacade>,
    document_keys_service: Arc<dyn DocumentKeysServiceFacade>,
    file_service: Arc<dyn FileServiceFacade>,
    public_service: Arc<dyn PublicServiceFacade>,
    share_service: Arc<dyn ShareServiceFacade>,
    tag_service: Arc<dyn TagServiceFacade>,
    auth_service: Arc<dyn AuthServiceFacade>,
    session_service: Arc<dyn UserSessionServiceFacade>,
    workspace_service: Arc<dyn WorkspaceServiceFacade>,
}

impl DocumentsContext {
    pub fn authorization(&self) -> Arc<dyn AuthorizationServiceFacade> {
        self.authorization.clone()
    }

    pub fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    pub fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }

    pub fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }

    pub fn share_service(&self) -> Arc<dyn ShareServiceFacade> {
        self.share_service.clone()
    }

    pub fn document_service(&self) -> Arc<dyn DocumentServiceFacade> {
        self.document_service.clone()
    }

    pub fn document_keys_service(&self) -> Arc<dyn DocumentKeysServiceFacade> {
        self.document_keys_service.clone()
    }

    pub fn file_service(&self) -> Arc<dyn FileServiceFacade> {
        self.file_service.clone()
    }

    pub fn public_service(&self) -> Arc<dyn PublicServiceFacade> {
        self.public_service.clone()
    }

    pub fn tag_service(&self) -> Arc<dyn TagServiceFacade> {
        self.tag_service.clone()
    }
}

impl HasAuthorizationService for DocumentsContext {
    fn authorization(&self) -> Arc<dyn AuthorizationServiceFacade> {
        self.authorization.clone()
    }
}

impl HasShareService for DocumentsContext {
    fn share_service(&self) -> Arc<dyn ShareServiceFacade> {
        self.share_service.clone()
    }
}

impl HasAuthServices for DocumentsContext {
    fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }
}

impl HasWorkspaceService for DocumentsContext {
    fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }
}

impl FromRef<AppContext> for DocumentsContext {
    fn from_ref(ctx: &AppContext) -> Self {
        Self {
            cfg: ctx.cfg.clone(),
            authorization: ctx.authorization(),
            document_service: ctx.document_service(),
            document_keys_service: ctx.document_keys_service(),
            file_service: ctx.file_service(),
            public_service: ctx.public_service(),
            share_service: ctx.share_service(),
            tag_service: ctx.tag_service(),
            auth_service: ctx.auth_service(),
            session_service: ctx.session_service(),
            workspace_service: ctx.workspace_service(),
        }
    }
}

#[derive(Clone)]
pub struct GitContext {
    pub cfg: PresentationConfig,
    git_service: Arc<dyn GitServiceFacade>,
    auth_service: Arc<dyn AuthServiceFacade>,
    session_service: Arc<dyn UserSessionServiceFacade>,
    workspace_service: Arc<dyn WorkspaceServiceFacade>,
}

impl GitContext {
    pub fn git_service(&self) -> Arc<dyn GitServiceFacade> {
        self.git_service.clone()
    }

    pub fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    pub fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }

    pub fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }
}

impl HasAuthServices for GitContext {
    fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }
}

impl HasWorkspaceService for GitContext {
    fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }
}

impl FromRef<AppContext> for GitContext {
    fn from_ref(ctx: &AppContext) -> Self {
        Self {
            cfg: ctx.cfg.clone(),
            git_service: ctx.git_service(),
            auth_service: ctx.auth_service(),
            session_service: ctx.session_service(),
            workspace_service: ctx.workspace_service(),
        }
    }
}

#[derive(Clone)]
pub struct IdentityContext {
    pub cfg: PresentationConfig,
    api_token_service: Arc<dyn ApiTokenServiceFacade>,
    user_shortcut_service: Arc<dyn UserShortcutServiceFacade>,
    user_keys_service: Arc<dyn UserKeysServiceFacade>,
    account_service: Arc<dyn AccountServiceFacade>,
    auth_service: Arc<dyn AuthServiceFacade>,
    session_service: Arc<dyn UserSessionServiceFacade>,
    external_auth: Arc<dyn ExternalAuthRegistryFacade>,
    workspace_service: Arc<dyn WorkspaceServiceFacade>,
}

impl IdentityContext {
    pub fn api_token_service(&self) -> Arc<dyn ApiTokenServiceFacade> {
        self.api_token_service.clone()
    }

    pub fn user_shortcut_service(&self) -> Arc<dyn UserShortcutServiceFacade> {
        self.user_shortcut_service.clone()
    }

    pub fn user_keys_service(&self) -> Arc<dyn UserKeysServiceFacade> {
        self.user_keys_service.clone()
    }

    pub fn account_service(&self) -> Arc<dyn AccountServiceFacade> {
        self.account_service.clone()
    }

    pub fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    pub fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }

    pub fn external_auth(&self) -> Arc<dyn ExternalAuthRegistryFacade> {
        self.external_auth.clone()
    }

    pub fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }
}

impl HasAuthServices for IdentityContext {
    fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }
}

impl HasWorkspaceService for IdentityContext {
    fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }
}

impl FromRef<AppContext> for IdentityContext {
    fn from_ref(ctx: &AppContext) -> Self {
        Self {
            cfg: ctx.cfg.clone(),
            api_token_service: ctx.api_token_service(),
            user_shortcut_service: ctx.user_shortcut_service(),
            user_keys_service: ctx.user_keys_service(),
            account_service: ctx.account_service(),
            auth_service: ctx.auth_service(),
            session_service: ctx.session_service(),
            external_auth: ctx.external_auth(),
            workspace_service: ctx.workspace_service(),
        }
    }
}

#[derive(Clone)]
pub struct PluginsContext {
    pub cfg: PresentationConfig,
    authorization: Arc<dyn AuthorizationServiceFacade>,
    plugin_execution_service: Arc<dyn PluginExecutionServiceFacade>,
    plugin_management_service: Arc<dyn PluginManagementServiceFacade>,
    plugin_permission_service: Arc<dyn PluginPermissionServiceFacade>,
    plugin_data_service: Arc<dyn PluginDataServiceFacade>,
    plugin_event_subscriber: Arc<dyn PluginEventSubscriber>,
    auth_service: Arc<dyn AuthServiceFacade>,
    session_service: Arc<dyn UserSessionServiceFacade>,
    workspace_service: Arc<dyn WorkspaceServiceFacade>,
    share_service: Arc<dyn ShareServiceFacade>,
}

impl PluginsContext {
    pub fn authorization(&self) -> Arc<dyn AuthorizationServiceFacade> {
        self.authorization.clone()
    }

    pub fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    pub fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }

    pub fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }

    pub fn share_service(&self) -> Arc<dyn ShareServiceFacade> {
        self.share_service.clone()
    }

    pub fn plugin_execution_service(&self) -> Arc<dyn PluginExecutionServiceFacade> {
        self.plugin_execution_service.clone()
    }

    pub fn plugin_management(&self) -> Arc<dyn PluginManagementServiceFacade> {
        self.plugin_management_service.clone()
    }

    pub fn plugin_permissions(&self) -> Arc<dyn PluginPermissionServiceFacade> {
        self.plugin_permission_service.clone()
    }

    pub fn plugin_data_service(&self) -> Arc<dyn PluginDataServiceFacade> {
        self.plugin_data_service.clone()
    }

    pub async fn subscribe_plugin_events(
        &self,
    ) -> anyhow::Result<BoxStream<'static, PluginScopedEvent>> {
        self.plugin_event_subscriber
            .subscribe()
            .await
            .map_err(Into::into)
    }
}

impl HasAuthorizationService for PluginsContext {
    fn authorization(&self) -> Arc<dyn AuthorizationServiceFacade> {
        self.authorization.clone()
    }
}

impl HasAuthServices for PluginsContext {
    fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }
}

impl HasWorkspaceService for PluginsContext {
    fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }
}

impl HasShareService for PluginsContext {
    fn share_service(&self) -> Arc<dyn ShareServiceFacade> {
        self.share_service.clone()
    }
}

impl FromRef<AppContext> for PluginsContext {
    fn from_ref(ctx: &AppContext) -> Self {
        Self {
            cfg: ctx.cfg.clone(),
            authorization: ctx.authorization(),
            plugin_execution_service: ctx.plugin_execution_service(),
            plugin_management_service: ctx.plugin_management(),
            plugin_permission_service: ctx.plugin_permissions(),
            plugin_data_service: ctx.plugin_data_service(),
            plugin_event_subscriber: ctx.plugin_event_subscriber(),
            auth_service: ctx.auth_service(),
            session_service: ctx.session_service(),
            workspace_service: ctx.workspace_service(),
            share_service: ctx.share_service(),
        }
    }
}

#[derive(Clone)]
pub struct WorkspacesContext {
    pub cfg: PresentationConfig,
    workspace_service: Arc<dyn WorkspaceServiceFacade>,
    workspace_keys_service: Arc<dyn WorkspaceKeysServiceFacade>,
    account_service: Arc<dyn AccountServiceFacade>,
    document_service: Arc<dyn DocumentServiceFacade>,
    auth_service: Arc<dyn AuthServiceFacade>,
    session_service: Arc<dyn UserSessionServiceFacade>,
}

impl WorkspacesContext {
    pub fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }

    pub fn workspace_keys_service(&self) -> Arc<dyn WorkspaceKeysServiceFacade> {
        self.workspace_keys_service.clone()
    }

    pub fn account_service(&self) -> Arc<dyn AccountServiceFacade> {
        self.account_service.clone()
    }

    pub fn document_service(&self) -> Arc<dyn DocumentServiceFacade> {
        self.document_service.clone()
    }

    pub fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    pub fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }
}

impl HasAuthServices for WorkspacesContext {
    fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }
}

impl HasWorkspaceService for WorkspacesContext {
    fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade> {
        self.workspace_service.clone()
    }
}

impl FromRef<AppContext> for WorkspacesContext {
    fn from_ref(ctx: &AppContext) -> Self {
        Self {
            cfg: ctx.cfg.clone(),
            workspace_service: ctx.workspace_service(),
            workspace_keys_service: ctx.workspace_keys_service(),
            account_service: ctx.account_service(),
            document_service: ctx.document_service(),
            auth_service: ctx.auth_service(),
            session_service: ctx.session_service(),
        }
    }
}

#[derive(Clone)]
pub struct WsContext {
    authorization: Arc<dyn AuthorizationServiceFacade>,
    realtime_engine: Arc<dyn RealtimeEngine>,
    auth_service: Arc<dyn AuthServiceFacade>,
    session_service: Arc<dyn UserSessionServiceFacade>,
}

impl WsContext {
    pub fn authorization(&self) -> Arc<dyn AuthorizationServiceFacade> {
        self.authorization.clone()
    }

    pub fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    pub fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }

    pub async fn subscribe_realtime(
        &self,
        doc_id: &str,
        sink: DynRealtimeSink,
        stream: DynRealtimeStream,
        can_edit: bool,
    ) -> anyhow::Result<()> {
        self.realtime_engine
            .subscribe(doc_id, sink, stream, can_edit)
            .await
            .map_err(Into::into)
    }
}

impl HasAuthServices for WsContext {
    fn auth_service(&self) -> Arc<dyn AuthServiceFacade> {
        self.auth_service.clone()
    }

    fn session_service(&self) -> Arc<dyn UserSessionServiceFacade> {
        self.session_service.clone()
    }
}

impl HasAuthorizationService for WsContext {
    fn authorization(&self) -> Arc<dyn AuthorizationServiceFacade> {
        self.authorization.clone()
    }
}

impl FromRef<AppContext> for WsContext {
    fn from_ref(ctx: &AppContext) -> Self {
        Self {
            authorization: ctx.authorization(),
            realtime_engine: ctx.realtime_engine(),
            auth_service: ctx.auth_service(),
            session_service: ctx.session_service(),
        }
    }
}
