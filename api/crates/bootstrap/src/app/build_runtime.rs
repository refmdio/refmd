use std::sync::Arc;

use tokio::time::Duration;
use tracing::info;

use application::documents::ports::doc_event_log::DocEventLog;
use application::plugins::ports::plugin_event_publisher::PluginEventPublisher;
use application::plugins::ports::plugin_event_subscriber::PluginEventSubscriber;
use application::core::ports::storage::storage_ingest_queue::StorageIngestQueue;
use application::core::ports::storage::storage_projection_queue::StorageProjectionQueue;
use application::core::ports::storage::storage_reconcile_jobs::StorageReconcileJobs;
use application::identity::services::api_tokens::ApiTokenService;
use application::identity::services::auth::account::AccountService;
use application::identity::services::auth::token_validation::TokenValidationService;
use application::core::services::authorization::AuthorizationService;
use application::core::services::doc_events::{
    DocEventSubscriber, FanoutDocEventSubscriber, LoggingDocEventSubscriber,
};
use application::documents::services::DocumentService;
use application::documents::services::files::FileService;
use application::core::services::health::HealthService;
use application::core::services::markdown_render::MarkdownRenderService;
use application::core::services::metrics::MetricsRegistry;
use application::plugins::services::asset_signer::AssetSigner;
use application::plugins::services::data::PluginDataService;
use application::plugins::services::execution::PluginExecutionService;
use application::plugins::services::management::PluginManagementService;
use application::plugins::services::permissions::PluginPermissionService;
use application::documents::services::publishing::PublicService;
use application::documents::services::realtime::snapshot::MarkdownExportProvider;
use application::documents::services::sharing::ShareService;
use application::core::services::storage::ingest::StorageIngestService;
use application::core::services::storage::reconcile::StorageReconcileService;
use application::core::services::storage::reconcile_scheduler::StorageReconcileScheduler;
use application::documents::services::tagging::TagService;
use application::identity::services::user_shortcuts::UserShortcutService;
use application::workspaces::services::{WorkspacePermissionResolver, WorkspaceService};
use infrastructure::documents::doc_event_log::PgDocEventLog;
use infrastructure::documents::event_poller::DocEventPoller;
use infrastructure::documents::exporter::DefaultDocumentExporter;
use infrastructure::documents::git_dirty_subscriber::GitDirtyDocEventSubscriber;
use infrastructure::core::storage::{
    FsIngestWatcher, PgStorageIngestQueue, PgStorageReconcileJobs, StorageConsistencyMonitor,
    StorageIngestWorker, StorageProjectionWorker,
};
use presentation::context::{AppContext, AppServices, PresentationConfig};

use crate::app::AppRuntime;
use crate::config::{Config, StorageBackend};
use crate::jobs::{self, Jobs};
use crate::{auth, git, plugins, realtime};

pub async fn build_runtime(cfg: Config, spawn_background_tasks: bool) -> anyhow::Result<AppRuntime> {
    info!(?cfg, "Starting RefMD backend");

    // Database
    let pool = infrastructure::core::db::connect_pool(&cfg.database_url).await?;
    infrastructure::core::db::migrate(&pool).await?;

    let asset_signer = Arc::new(AssetSigner::new(&cfg.plugin_asset_sign_key));
    let uploads_root = std::path::PathBuf::from(&cfg.storage_root);
    let (storage_resolver, storage_projection, reconcile_backend, reconcile_ingest_known_paths) =
        crate::storage::build_storage_ports(&cfg, &pool).await?;

    let storage_job_queue: Arc<dyn StorageProjectionQueue> =
        crate::storage::build_storage_projection_queue(&pool);
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
        jobs::spawn_storage_consistency_monitor(&mut jobs, true, spawn_background_tasks, monitor);
    } else {
        tracing::info!("storage_consistency_monitor_disabled");
    }

    let snapshot_archive_repo: Arc<
        dyn application::documents::ports::document_snapshot_archive_repository::DocumentSnapshotArchiveRepository,
    > = Arc::new(
        infrastructure::documents::db::repositories::document_snapshot_archive_repository_sqlx::SqlxDocumentSnapshotArchiveRepository::new(
            pool.clone(),
        ),
    );
    let document_repo = Arc::new(
        infrastructure::documents::db::repositories::document_repository_sqlx::SqlxDocumentRepository::new(
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
        use domain::storage::ingest_backend::StorageIngestBackend;
        let watcher = Arc::new(FsIngestWatcher::new(
            uploads_root.clone(),
            storage_ingest_queue.clone(),
            StorageIngestBackend::FsWatcher,
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
        infrastructure::documents::db::repositories::shares_repository_sqlx::SqlxSharesRepository::new(
            pool.clone(),
        ),
    );
    let share_service = Arc::new(ShareService::new(shares_repo_impl.clone()));
    let access_repo = Arc::new(
        infrastructure::documents::db::repositories::access_repository_sqlx::SqlxAccessRepository::new(
            pool.clone(),
        ),
    );
    let authorization_service = Arc::new(AuthorizationService::new(
        access_repo.clone(),
        shares_repo_impl.clone(),
    ));
    let files_repo = Arc::new(
        infrastructure::documents::db::repositories::files_repository_sqlx::SqlxFilesRepository::new(
            pool.clone(),
        ),
    );
    let documents_tx_runner: Arc<dyn application::documents::ports::tx_runner::DocumentsTxRunner> =
        Arc::new(infrastructure::documents::tx_runner_sqlx::SqlxDocumentsTxRunner::new(
            pool.clone(),
            document_repo.clone(),
            files_repo.clone(),
        ));
    let public_repo = Arc::new(
        infrastructure::documents::db::repositories::public_repository_sqlx::SqlxPublicRepository::new(
            pool.clone(),
        ),
    );
    let user_repo = Arc::new(
        infrastructure::identity::db::repositories::user_repository_sqlx::SqlxUserRepository::new(
            pool.clone(),
        ),
    );
    let workspace_repo = Arc::new(
        infrastructure::workspaces::db::repositories::workspace_repository_sqlx::SqlxWorkspaceRepository::new(
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
        jobs::spawn_storage_reconcile_worker(&mut jobs, spawn_background_tasks, reconcile_service);
        let scheduler = StorageReconcileScheduler::new(
            storage_reconcile_jobs.clone(),
            workspace_repo.clone(),
            Duration::from_secs(60 * 60),
        );
        jobs::spawn_storage_reconcile_scheduler(&mut jobs, spawn_background_tasks, scheduler);
    }
    let tag_repo = Arc::new(
        infrastructure::documents::db::repositories::tag_repository_sqlx::SqlxTagRepository::new(pool.clone()),
    );
    let tag_service = Arc::new(TagService::new(tag_repo.clone()));
    let api_token_repo = Arc::new(
        infrastructure::identity::db::repositories::api_token_repository_sqlx::SqlxApiTokenRepository::new(
            pool.clone(),
        ),
    );
    let api_token_service = Arc::new(ApiTokenService::new(api_token_repo.clone()));
    let token_validation_service = Arc::new(TokenValidationService::new(api_token_repo.clone()));
    let user_session_repo = Arc::new(
        infrastructure::identity::db::repositories::user_session_repository_sqlx::SqlxUserSessionRepository::new(
            pool.clone(),
        ),
    );
    let auth_stack =
        auth::build_auth_stack(&cfg, token_validation_service, user_session_repo.clone()).await?;

    jobs::spawn_session_cleanup(
        &mut jobs,
        spawn_background_tasks,
        user_session_repo.clone(),
        jobs::SESSION_CLEANUP_INTERVAL_SECS,
        jobs::SESSION_CLEANUP_BATCH_SIZE,
    );
    let user_shortcuts = Arc::new(
        infrastructure::identity::db::repositories::user_shortcut_repository_sqlx::SqlxUserShortcutRepository::new(
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
        application::core::services::storage::projection_cache::RecentProjectionCache::new(
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

    let crate::git::GitStack {
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
        infrastructure::plugins::db::repositories::plugin_repository_sqlx::SqlxPluginRepository::new(
            pool.clone(),
        ),
    );
    let plugin_data_service = Arc::new(PluginDataService::new(plugin_repo.clone()));
    let plugin_installations = Arc::new(
        infrastructure::plugins::db::repositories::plugin_installation_repository_sqlx::SqlxPluginInstallationRepository::new(
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
    let plugin_event_bus = Arc::new(infrastructure::plugins::event_bus_pg::PgPluginEventBus::new(
        pool.clone(),
        "plugin_events",
    ));
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
        documents_tx_runner,
        document_repo.clone(),
        files_repo.clone(),
        access_repo.clone(),
        shares_repo_impl.clone(),
        storage_resolver.clone(),
        doc_event_log.clone(),
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
    let public_service = Arc::new(PublicService::new(public_repo.clone(), realtime_engine.clone()));
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

    let health_probe = infrastructure::core::health::db_probe::DatabaseHealthProbe::new(pool.clone());
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
