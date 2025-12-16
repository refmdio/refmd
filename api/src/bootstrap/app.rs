use std::net::SocketAddr;
use std::sync::Arc;

use dotenvy::dotenv;
use tokio::time::Duration;
use tracing::{error, info};

// Allow using the crate name `api::` for intra-crate references.
use crate as api;

use api::application::ports::doc_event_log::DocEventLog;
use api::application::ports::git_rebuild_job_queue::GitRebuildJobQueue;
use api::application::ports::plugin_asset_store::PluginAssetStore;
use api::application::ports::plugin_event_publisher::PluginEventPublisher;
use api::application::ports::plugin_event_subscriber::PluginEventSubscriber;
use api::application::ports::storage_ingest_queue::StorageIngestQueue;
use api::application::ports::storage_projection_queue::StorageProjectionQueue;
use api::application::ports::storage_reconcile_jobs::StorageReconcileJobs;
use api::application::services::api_tokens::ApiTokenService;
use api::application::services::auth::account::AccountService;
use api::application::services::auth::token_validation::TokenValidationService;
use api::application::services::authorization::AuthorizationService;
use api::application::services::doc_events::{
    DocEventSubscriber, FanoutDocEventSubscriber, LoggingDocEventSubscriber,
};
use api::application::services::documents::DocumentService;
use api::application::services::files::FileService;
use api::application::services::health::HealthService;
use api::application::services::markdown_render::MarkdownRenderService;
use api::application::services::metrics::MetricsRegistry;
use api::application::services::plugins::asset_signer::AssetSigner;
use api::application::services::plugins::data::PluginDataService;
use api::application::services::plugins::execution::PluginExecutionService;
use api::application::services::plugins::management::PluginManagementService;
use api::application::services::plugins::permissions::PluginPermissionService;
use api::application::services::public::PublicService;
use api::application::services::realtime::snapshot::MarkdownExportProvider;
use api::application::services::shares::ShareService;
use api::application::services::storage_ingest::StorageIngestService;
use api::application::services::storage_reconcile::StorageReconcileService;
use api::application::services::storage_reconcile_scheduler::StorageReconcileScheduler;
use api::application::services::tags::TagService;
use api::application::services::user_shortcuts::UserShortcutService;
use api::application::services::workspaces::{WorkspacePermissionResolver, WorkspaceService};
use api::bootstrap::auth;
use api::bootstrap::config::{Config, StorageBackend};
use api::bootstrap::git::{self, GitStack};
use api::bootstrap::jobs::{self, Jobs};
use api::bootstrap::{http, plugins, realtime, telemetry};
use api::infrastructure::db::PgPool;
use api::infrastructure::documents::doc_event_log::PgDocEventLog;
use api::infrastructure::documents::event_poller::DocEventPoller;
use api::infrastructure::documents::exporter::DefaultDocumentExporter;
use api::infrastructure::documents::git_dirty_subscriber::GitDirtyDocEventSubscriber;
use api::infrastructure::storage::{
    FsIngestWatcher, PgStorageIngestQueue, PgStorageReconcileJobs, StorageConsistencyMonitor,
    StorageIngestWorker, StorageProjectionWorker,
};
use api::presentation::context::{AppContext, AppServices, PresentationConfig};

pub struct AppBuilder {
    cfg: Config,
    spawn_background_tasks: bool,
}

pub struct AppRuntime {
    cfg: Config,
    pool: PgPool,
    ctx: AppContext,
    local_hub: Option<api::infrastructure::realtime::Hub>,
    jobs: Jobs,
    storage_job_queue: Arc<dyn StorageProjectionQueue>,
    storage_reconcile_jobs: Arc<dyn StorageReconcileJobs>,
    git_rebuild_jobs: Arc<dyn GitRebuildJobQueue>,
    plugin_assets: Arc<dyn PluginAssetStore>,
}

impl AppBuilder {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenv().ok();

        telemetry::init_tracing();

        let cfg = Config::from_env()?;
        Ok(Self {
            cfg,
            spawn_background_tasks: true,
        })
    }

    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            spawn_background_tasks: true,
        }
    }

    /// Enable or disable background tasks (useful for CLI/tests).
    pub fn with_background_tasks(mut self, enabled: bool) -> Self {
        self.spawn_background_tasks = enabled;
        self
    }

    pub async fn build(self) -> anyhow::Result<AppRuntime> {
        build_runtime(self.cfg, self.spawn_background_tasks).await
    }
}

impl AppRuntime {
    /// Consume the runtime and return owned parts for reuse.
    pub fn into_parts(
        self,
    ) -> (
        Config,
        PgPool,
        AppContext,
        Option<api::infrastructure::realtime::Hub>,
        Jobs,
        Arc<dyn StorageProjectionQueue>,
        Arc<dyn StorageReconcileJobs>,
        Arc<dyn GitRebuildJobQueue>,
        Arc<dyn PluginAssetStore>,
    ) {
        (
            self.cfg,
            self.pool,
            self.ctx,
            self.local_hub,
            self.jobs,
            self.storage_job_queue,
            self.storage_reconcile_jobs,
            self.git_rebuild_jobs,
            self.plugin_assets,
        )
    }

    pub async fn serve(self) -> anyhow::Result<()> {
        let AppRuntime {
            cfg,
            ctx,
            pool,
            local_hub,
            mut jobs,
            storage_job_queue: _,
            storage_reconcile_jobs: _,
            git_rebuild_jobs: _,
            plugin_assets: _,
        } = self;

        let api_router = http::build_api_router(&cfg, ctx.clone()).await?;

        // Mount WS endpoint on the same port as HTTP

        // Compose final app for HTTP
        let api_addr = SocketAddr::from(([0, 0, 0, 0], cfg.api_port));
        info!(%api_addr, "HTTP API listening");
        let listener = tokio::net::TcpListener::bind(api_addr).await?;
        let ws_router = http::build_ws_router(ctx.clone());

        let app = api_router.merge(ws_router);

        jobs::spawn_snapshot_loop(&mut jobs, true, local_hub.clone(), cfg.clone(), pool.clone());

        let server = axum::serve(listener, app).with_graceful_shutdown(jobs::wait_for_shutdown_signal());
        match server.await {
            Ok(()) => {}
            Err(e) => error!(?e, "API server failed"),
        }

        // Abort background jobs on exit.
        jobs.shutdown().await;
        Ok(())
    }
}

pub async fn run() -> anyhow::Result<()> {
    AppBuilder::from_env()?.build().await?.serve().await
}

/// Build the application runtime (infrastructure + services) without starting servers.
pub async fn build_runtime(
    cfg: Config,
    spawn_background_tasks: bool,
) -> anyhow::Result<AppRuntime> {
    info!(?cfg, "Starting RefMD backend");

    // Database
    let pool = api::infrastructure::db::connect_pool(&cfg.database_url).await?;
    api::infrastructure::db::migrate(&pool).await?;

    let asset_signer = Arc::new(AssetSigner::new(&cfg.plugin_asset_sign_key));
    let uploads_root = std::path::PathBuf::from(&cfg.storage_root);
    let (storage_resolver, storage_projection, reconcile_backend, reconcile_ingest_known_paths) =
        api::bootstrap::storage::build_storage_ports(&cfg, &pool).await?;

    let storage_job_queue: Arc<dyn StorageProjectionQueue> =
        api::bootstrap::storage::build_storage_projection_queue(&pool);
    let storage_ingest_queue: Arc<dyn StorageIngestQueue> =
        Arc::new(PgStorageIngestQueue::new(pool.clone()));
    let mut jobs = Jobs::new();

    if cfg.storage_monitor_enabled {
        let monitor = Arc::new(StorageConsistencyMonitor::new(
            pool.clone(),
            storage_resolver.clone(),
            storage_job_queue.clone(),
            storage_ingest_queue.clone(),
            Duration::from_secs(cfg.storage_monitor_interval_secs),
            cfg.storage_monitor_batch_size,
        ));
        tracing::info!(
            interval_secs = cfg.storage_monitor_interval_secs,
            batch_size = cfg.storage_monitor_batch_size,
            "storage_consistency_monitor_enabled"
        );
        jobs::spawn_storage_consistency_monitor(
            &mut jobs,
            true,
            spawn_background_tasks,
            monitor,
        );
    } else {
        tracing::info!("storage_consistency_monitor_disabled");
    }

    let snapshot_archive_repo: Arc<
        dyn api::application::ports::document_snapshot_archive_repository::DocumentSnapshotArchiveRepository,
    > = Arc::new(
        api::infrastructure::db::repositories::document_snapshot_archive_repository_sqlx::SqlxDocumentSnapshotArchiveRepository::new(
            pool.clone(),
        ),
    );
    let document_repo = Arc::new(
        api::infrastructure::db::repositories::document_repository_sqlx::SqlxDocumentRepository::new(
            pool.clone(),
        ),
    );
    let doc_event_log: Arc<dyn DocEventLog> = Arc::new(PgDocEventLog::new(pool.clone()));
    let metrics = Arc::new(MetricsRegistry::default());
    let storage_reconcile_jobs: Arc<dyn StorageReconcileJobs> =
        Arc::new(PgStorageReconcileJobs::new(pool.clone()));
    let logging_subscriber: Arc<dyn DocEventSubscriber> = LoggingDocEventSubscriber::new();
    let git_dirty_subscriber: Arc<dyn DocEventSubscriber> =
        GitDirtyDocEventSubscriber::new(pool.clone());
    let doc_event_subscriber: Arc<dyn DocEventSubscriber> =
        FanoutDocEventSubscriber::new(vec![logging_subscriber.clone(), git_dirty_subscriber]);
    if matches!(cfg.storage_backend, StorageBackend::Filesystem) {
        let watcher = Arc::new(FsIngestWatcher::new(
            uploads_root.clone(),
            storage_ingest_queue.clone(),
            "fs_watcher",
        ));
        jobs::spawn_fs_ingest_watcher(&mut jobs, spawn_background_tasks, watcher);
    }
    {
        let poller = Arc::new(DocEventPoller::new(
            pool.clone(),
            doc_event_subscriber.clone(),
            Duration::from_millis(500),
            200,
            "doc_event_poller",
        ));
        jobs::spawn_doc_event_poller(&mut jobs, spawn_background_tasks, poller);
    }
    let shares_repo_impl = Arc::new(
        api::infrastructure::db::repositories::shares_repository_sqlx::SqlxSharesRepository::new(
            pool.clone(),
        ),
    );
    let share_service = Arc::new(ShareService::new(shares_repo_impl.clone()));
    let access_repo = Arc::new(
        api::infrastructure::db::repositories::access_repository_sqlx::SqlxAccessRepository::new(
            pool.clone(),
        ),
    );
    let authorization_service = Arc::new(AuthorizationService::new(
        access_repo.clone(),
        shares_repo_impl.clone(),
    ));
    let files_repo = Arc::new(
        api::infrastructure::db::repositories::files_repository_sqlx::SqlxFilesRepository::new(
            pool.clone(),
        ),
    );
    let public_repo = Arc::new(
        api::infrastructure::db::repositories::public_repository_sqlx::SqlxPublicRepository::new(
            pool.clone(),
        ),
    );
    let user_repo = Arc::new(
        api::infrastructure::db::repositories::user_repository_sqlx::SqlxUserRepository::new(
            pool.clone(),
        ),
    );
    let workspace_repo = Arc::new(
        api::infrastructure::db::repositories::workspace_repository_sqlx::SqlxWorkspaceRepository::new(
            pool.clone(),
        ),
    );
    let workspace_service = Arc::new(WorkspaceService::new(workspace_repo.clone()));
    let workspace_permissions: Arc<dyn WorkspacePermissionResolver> = workspace_service.clone();
    {
        let reconcile_service = Arc::new(StorageReconcileService::new(
            storage_reconcile_jobs.clone(),
            document_repo.clone(),
            files_repo.clone(),
            storage_ingest_queue.clone(),
            storage_job_queue.clone(),
            reconcile_backend.clone(),
            reconcile_ingest_known_paths,
        ));
        jobs::spawn_storage_reconcile_worker(
            &mut jobs,
            spawn_background_tasks,
            reconcile_service.clone(),
        );
        let scheduler = StorageReconcileScheduler::new(
            storage_reconcile_jobs.clone(),
            workspace_repo.clone(),
            Duration::from_secs(60 * 60),
        );
        jobs::spawn_storage_reconcile_scheduler(&mut jobs, spawn_background_tasks, scheduler);
    }
    let tag_repo = Arc::new(
        api::infrastructure::db::repositories::tag_repository_sqlx::SqlxTagRepository::new(
            pool.clone(),
        ),
    );
    let tag_service = Arc::new(TagService::new(tag_repo.clone()));
    let api_token_repo = Arc::new(
        api::infrastructure::db::repositories::api_token_repository_sqlx::SqlxApiTokenRepository::new(
            pool.clone(),
        ),
    );
    let api_token_service = Arc::new(ApiTokenService::new(api_token_repo.clone()));
    let token_validation_service = Arc::new(TokenValidationService::new(api_token_repo.clone()));
    let user_session_repo = Arc::new(
        api::infrastructure::db::repositories::user_session_repository_sqlx::SqlxUserSessionRepository::new(
            pool.clone(),
        ),
    );
    let auth_stack = auth::build_auth_stack(
        &cfg,
        token_validation_service.clone(),
        user_session_repo.clone(),
    )
    .await?;

    jobs::spawn_session_cleanup(
        &mut jobs,
        spawn_background_tasks,
        user_session_repo.clone(),
        jobs::SESSION_CLEANUP_INTERVAL_SECS,
        jobs::SESSION_CLEANUP_BATCH_SIZE,
    );
    let user_shortcuts = Arc::new(
        api::infrastructure::db::repositories::user_shortcut_repository_sqlx::SqlxUserShortcutRepository::new(
            pool.clone(),
        ),
    );
    let user_shortcut_service =
        Arc::new(UserShortcutService::new(user_shortcuts.clone(), 32 * 1024));
    let realtime_stack = realtime::build_realtime_stack(
        &cfg,
        &pool,
        storage_resolver.clone(),
        storage_job_queue.clone(),
        snapshot_archive_repo.clone(),
    )
    .await?;
    let local_hub = realtime_stack.local_hub.clone();
    let realtime_engine = realtime_stack.engine.clone();
    let snapshot_service_arc = realtime_stack.snapshot_service.clone();

    let recent_projection_cache = Arc::new(
        api::application::services::storage_projection_cache::RecentProjectionCache::new(
            Duration::from_secs(5),
        ),
    );

    {
        let markdown_exporter: Arc<dyn MarkdownExportProvider> = snapshot_service_arc.clone();
        let worker = Arc::new(StorageProjectionWorker::new(
            storage_job_queue.clone(),
            storage_projection.clone(),
            storage_resolver.clone(),
            markdown_exporter,
            doc_event_log.clone(),
            metrics.clone(),
            workspace_permissions.clone(),
            recent_projection_cache.clone(),
        ));
        jobs::spawn_storage_projection_worker(&mut jobs, spawn_background_tasks, worker);
    }

    let GitStack {
        workspace: git_workspace,
        service: git_service,
        repo: git_repo,
        rebuild,
        rebuild_jobs: git_rebuild_jobs,
    } = git::build_git_stack(
        &cfg,
        &pool,
        storage_resolver.clone(),
        snapshot_service_arc.clone(),
        realtime_engine.clone(),
        document_repo.clone(),
        files_repo.clone(),
        workspace_permissions.clone(),
        metrics.clone(),
    )
    .await?;

    jobs::spawn_git_rebuild_jobs(&mut jobs, spawn_background_tasks, rebuild);
    let plugin_repo = Arc::new(
        api::infrastructure::db::repositories::plugin_repository_sqlx::SqlxPluginRepository::new(
            pool.clone(),
        ),
    );
    let plugin_data_service = Arc::new(PluginDataService::new(plugin_repo.clone()));
    let plugin_installations = Arc::new(
        api::infrastructure::db::repositories::plugin_installation_repository_sqlx::SqlxPluginInstallationRepository::new(
            pool.clone(),
        ),
    );
    let plugin_limits = plugins::build_plugin_execution_limits(&cfg);
    let (plugin_runtime, plugin_installer, plugin_assets, s3_plugin_store, plugin_fetcher) =
        plugins::build_plugin_stack(&cfg, plugin_limits).await?;
    let plugin_permission_service = Arc::new(PluginPermissionService::new(plugin_runtime.clone()));
    let plugin_execution_service = Arc::new(PluginExecutionService::new(
        plugin_repo.clone(),
        document_repo.clone(),
        plugin_runtime.clone(),
        authorization_service.clone(),
    ));
    let account_service = Arc::new(AccountService::new(
        user_repo.clone(),
        document_repo.clone(),
        files_repo.clone(),
        plugin_installations.clone(),
        plugin_repo.clone(),
        plugin_assets.clone(),
        git_repo.clone(),
        git_workspace.clone(),
        storage_job_queue.clone(),
        workspace_service.clone(),
    ));
    let plugin_event_bus = Arc::new(
        api::infrastructure::plugins::event_bus_pg::PgPluginEventBus::new(
            pool.clone(),
            "plugin_events",
        ),
    );
    if let Some(store) = &s3_plugin_store {
        store.spawn_event_listener(plugin_event_bus.clone());

        let installations = plugin_installations.clone();
        let assets = store.clone();
        jobs::spawn_plugin_prefetch(&mut jobs, spawn_background_tasks, installations, assets);
    }
    let plugin_event_publisher: Arc<dyn PluginEventPublisher> = plugin_event_bus.clone();
    let plugin_event_subscriber: Arc<dyn PluginEventSubscriber> = plugin_event_bus.clone();

    let document_exporter = Arc::new(DefaultDocumentExporter::new());

    let document_service = Arc::new(DocumentService::new(
        pool.clone(),
        document_repo.clone(),
        files_repo.clone(),
        access_repo.clone(),
        shares_repo_impl.clone(),
        storage_resolver.clone(),
        doc_event_log.clone(),
        storage_job_queue.clone(),
        realtime_engine.clone(),
        snapshot_service_arc.clone(),
        document_exporter.clone(),
    ));

    {
        let handler = Arc::new(StorageIngestService::new(
            document_repo.clone(),
            files_repo.clone(),
            realtime_engine.clone(),
            storage_resolver.clone(),
            storage_projection.clone(),
            doc_event_log.clone(),
            document_service.clone(),
            workspace_permissions.clone(),
            recent_projection_cache.clone(),
        ));
        let worker = Arc::new(StorageIngestWorker::new(
            storage_ingest_queue.clone(),
            handler,
            metrics.clone(),
        ));
        jobs::spawn_storage_ingest_worker(&mut jobs, spawn_background_tasks, worker);
    }
    let file_service = Arc::new(FileService::new(
        files_repo.clone(),
        storage_resolver.clone(),
        access_repo.clone(),
        shares_repo_impl.clone(),
        doc_event_log.clone(),
    ));
    let public_service = Arc::new(PublicService::new(
        public_repo.clone(),
        realtime_engine.clone(),
    ));
    let plugin_management_service = Arc::new(PluginManagementService::new(
        plugin_installations.clone(),
        plugin_assets.clone(),
        plugin_event_publisher.clone(),
        asset_signer.clone(),
        cfg.plugin_asset_url_ttl_secs,
        plugin_fetcher.clone(),
        plugin_installer.clone(),
    ));
    let markdown_render_service = Arc::new(MarkdownRenderService::new(
        plugin_assets.clone(),
        plugin_installations.clone(),
        plugin_runtime.clone(),
        asset_signer.clone(),
        cfg.plugin_asset_url_ttl_secs,
    ));

    let health_probe =
        api::infrastructure::health::db_probe::DatabaseHealthProbe::new(pool.clone());
    let health_service = Arc::new(HealthService::new(health_probe));

    let external_auth_registry = auth_stack.external_auth.clone();

    let services = AppServices::new(
        authorization_service,
        document_service.clone(),
        share_service.clone(),
        file_service.clone(),
        public_service.clone(),
        tag_service.clone(),
        api_token_service.clone(),
        user_shortcut_service.clone(),
        git_service.clone(),
        markdown_render_service.clone(),
        workspace_service.clone(),
        plugin_execution_service.clone(),
        plugin_management_service.clone(),
        plugin_permission_service.clone(),
        plugin_data_service.clone(),
        plugin_event_subscriber,
        health_service.clone(),
        account_service.clone(),
        auth_stack.auth_service.clone(),
        auth_stack.session_service.clone(),
        realtime_engine.clone(),
        storage_ingest_queue.clone(),
        external_auth_registry.clone(),
    );

    let presentation_cfg = PresentationConfig {
        frontend_url: cfg.frontend_url.clone(),
        upload_max_bytes: cfg.upload_max_bytes,
        public_base_url: cfg.public_base_url.clone(),
        session_cookie_secure: auth_stack.cookie_secure,
    };
    let ctx = AppContext::new(presentation_cfg, services, metrics.clone());

    Ok(AppRuntime {
        cfg,
        pool,
        ctx,
        local_hub,
        jobs,
        storage_job_queue,
        storage_reconcile_jobs,
        git_rebuild_jobs,
        plugin_assets,
    })
}
