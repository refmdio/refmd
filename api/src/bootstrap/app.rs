use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use chrono::Utc;
use dotenvy::dotenv;
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};
use tracing::{debug, error, info, warn};

// Allow using the crate name `api::` for intra-crate references.
use crate as api;

use api::application::ports::doc_event_log::DocEventLog;
use api::application::ports::git_rebuild_job_queue::GitRebuildJobQueue;
use api::application::ports::plugin_asset_store::PluginAssetStore;
use api::application::ports::plugin_event_publisher::PluginEventPublisher;
use api::application::ports::plugin_event_subscriber::PluginEventSubscriber;
use api::application::ports::plugin_installation_repository::PluginInstallationRepository;
use api::application::ports::storage_ingest_queue::StorageIngestQueue;
use api::application::ports::storage_projection_queue::StorageProjectionQueue;
use api::application::ports::storage_reconcile_jobs::StorageReconcileJobs;
use api::application::ports::user_session_repository::UserSessionRepository;
use api::application::services::api_tokens::ApiTokenService;
use api::application::services::auth::account::AccountService;
use api::application::services::auth::external::{ExternalAuthRegistry, ExternalAuthVerifier};
use api::application::services::auth::service::AuthService;
use api::application::services::auth::token_validation::TokenValidationService;
use api::application::services::auth::user_sessions::UserSessionService;
use api::application::services::authorization::AuthorizationService;
use api::application::services::doc_events::{
    DocEventSubscriber, FanoutDocEventSubscriber, LoggingDocEventSubscriber,
};
use api::application::services::documents::DocumentService;
use api::application::services::files::FileService;
use api::application::services::git::GitService;
use api::application::services::git_rebuild::GitRebuildService;
use api::application::services::git_rebuild_scheduler::GitRebuildScheduler;
use api::application::services::health::HealthService;
use api::application::services::markdown_render::MarkdownRenderService;
use api::application::services::metrics::MetricsRegistry;
use api::application::services::plugins::asset_signer::AssetSigner;
use api::application::services::plugins::data::PluginDataService;
use api::application::services::plugins::execution::PluginExecutionService;
use api::application::services::plugins::management::PluginManagementService;
use api::application::services::plugins::permissions::PluginPermissionService;
use api::application::services::public::PublicService;
use api::application::services::realtime::snapshot::{MarkdownExportProvider, SnapshotService};
use api::application::services::shares::ShareService;
use api::application::services::storage_ingest::StorageIngestService;
use api::application::services::storage_reconcile::StorageReconcileService;
use api::application::services::storage_reconcile_scheduler::StorageReconcileScheduler;
use api::application::services::tags::TagService;
use api::application::services::user_shortcuts::UserShortcutService;
use api::application::services::workspaces::{WorkspacePermissionResolver, WorkspaceService};
use api::bootstrap::config::{Config, StorageBackend};
use api::bootstrap::{http, jobs::Jobs, plugins, telemetry};
use api::infrastructure::auth::github::GithubOAuthProvider;
use api::infrastructure::auth::google::GoogleIdentityProvider;
use api::infrastructure::auth::oidc::OidcIdentityProvider;
use api::infrastructure::db::PgPool;
use api::infrastructure::db::advisory_lock::AdvisoryLock;
use api::infrastructure::documents::doc_event_log::PgDocEventLog;
use api::infrastructure::documents::event_poller::DocEventPoller;
use api::infrastructure::documents::exporter::DefaultDocumentExporter;
use api::infrastructure::documents::git_dirty_subscriber::GitDirtyDocEventSubscriber;
use api::infrastructure::git::PgGitRebuildJobQueue;
use api::infrastructure::git::storage::GitStorageDriverConfig;
use api::infrastructure::storage::{
    FsIngestWatcher, PgStorageIngestQueue, PgStorageReconcileJobs, StorageConsistencyMonitor,
    StorageIngestWorker, StorageProjectionWorker,
};
use api::presentation::context::{AppContext, AppServices, PresentationConfig};

const SESSION_CLEANUP_INTERVAL_SECS: u64 = 15 * 60;
const SESSION_CLEANUP_BATCH_SIZE: i64 = 500;

pub fn git_storage_driver_config(cfg: &Config) -> anyhow::Result<GitStorageDriverConfig> {
    let uploads_root = std::path::PathBuf::from(&cfg.storage_root);
    let config = match cfg.storage_backend {
        StorageBackend::Filesystem => GitStorageDriverConfig::Filesystem {
            root: uploads_root.clone(),
        },
        StorageBackend::S3 => {
            let s3_settings = api::infrastructure::git::storage::S3GitStorageConfig {
                storage_root_prefix: cfg.storage_root.clone(),
                bucket: cfg
                    .s3_bucket
                    .clone()
                    .context("S3_BUCKET must be configured when using S3 storage backend")?,
                region: cfg.s3_region.clone(),
                endpoint: cfg.s3_endpoint.clone(),
                access_key: cfg.s3_access_key.clone(),
                secret_key: cfg.s3_secret_key.clone(),
                use_path_style: cfg.s3_use_path_style,
            };
            GitStorageDriverConfig::S3(s3_settings)
        }
    };
    Ok(config)
}

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

        let api_handle: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            axum::serve(listener, app).await?;
            Ok(())
        });

        // Background snapshots
        const SNAPSHOT_LOCK_KEY: i64 = i64::from_be_bytes(*b"REFSNAP1");

        if let Some(hub_for_snap) = local_hub.clone() {
            let cfg_for_snap = cfg.clone();
            let pool_for_snap = pool.clone();
            jobs.spawn("snapshot_loop", async move {
                let interval = Duration::from_secs(cfg_for_snap.snapshot_interval_secs);
                loop {
                    match AdvisoryLock::try_acquire(&pool_for_snap, SNAPSHOT_LOCK_KEY).await {
                        Ok(Some(lock)) => {
                            let snapshot_result = hub_for_snap
                                .snapshot_all(
                                    cfg_for_snap.snapshot_keep_versions,
                                    cfg_for_snap.updates_keep_window,
                                )
                                .await;

                            if let Err(e) = lock.release().await {
                                tracing::error!(error = ?e, "snapshot_lock_release_failed");
                            }

                            if let Err(e) = snapshot_result {
                                tracing::error!(error = ?e, "snapshot_loop_failed");
                            }
                        }
                        Ok(None) => {
                            tracing::debug!("snapshot_loop_skipped_lock_held");
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "snapshot_lock_error");
                        }
                    }
                    sleep(interval).await;
                }
            });
        }

        match api_handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(?e, "API server task failed"),
            Err(e) => error!(?e, "API server task panicked"),
        }
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
        if spawn_background_tasks {
            jobs.spawn("storage_consistency_monitor", async move {
                monitor.run().await;
            });
        }
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
    let git_rebuild_jobs: Arc<dyn GitRebuildJobQueue> =
        Arc::new(PgGitRebuildJobQueue::new(pool.clone()));
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
        if spawn_background_tasks {
            jobs.spawn("fs_ingest_watcher", async move {
                watcher.run().await;
            });
        }
    }
    {
        let poller = Arc::new(DocEventPoller::new(
            pool.clone(),
            doc_event_subscriber.clone(),
            Duration::from_millis(500),
            200,
            "doc_event_poller",
        ));
        if spawn_background_tasks {
            jobs.spawn("doc_event_poller", async move {
                poller.run().await;
            });
        }
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
        if spawn_background_tasks {
            jobs.spawn("storage_reconcile_worker", {
                let svc = reconcile_service.clone();
                async move {
                    svc.run().await;
                }
            });
        }
        let scheduler = StorageReconcileScheduler::new(
            storage_reconcile_jobs.clone(),
            workspace_repo.clone(),
            Duration::from_secs(60 * 60),
        );
        if spawn_background_tasks {
            jobs.spawn("storage_reconcile_scheduler", async move {
                scheduler.run().await;
            });
        }
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
    let cookie_secure = cfg
        .frontend_url
        .as_deref()
        .map(|u| u.starts_with("https://"))
        .unwrap_or(false);
    let auth_service = Arc::new(AuthService::new(
        cfg.jwt_secret_pem.clone(),
        token_validation_service.clone(),
        cfg.jwt_expires_secs as usize,
    ));
    let user_session_repo = Arc::new(
        api::infrastructure::db::repositories::user_session_repository_sqlx::SqlxUserSessionRepository::new(
            pool.clone(),
        ),
    );
    let session_service = Arc::new(UserSessionService::new(
        user_session_repo.clone(),
        auth_service.clone(),
        cfg.session_refresh_ttl_secs,
        cfg.session_refresh_remember_ttl_secs,
    ));

    if spawn_background_tasks {
        let repo = user_session_repo.clone();
        jobs.spawn("session_cleanup", async move {
            let mut ticker =
                tokio::time::interval(Duration::from_secs(SESSION_CLEANUP_INTERVAL_SECS));
            loop {
                ticker.tick().await;
                let cutoff = Utc::now();
                let mut total_removed: u64 = 0;
                loop {
                    match repo
                        .delete_expired(cutoff, SESSION_CLEANUP_BATCH_SIZE)
                        .await
                    {
                        Ok(removed) => {
                            if removed == 0 {
                                break;
                            }
                            total_removed += removed;
                            if removed < SESSION_CLEANUP_BATCH_SIZE as u64 {
                                break;
                            }
                        }
                        Err(err) => {
                            warn!(error = ?err, "user_session_cleanup_failed");
                            break;
                        }
                    }
                }
                if total_removed > 0 {
                    debug!(removed = total_removed, "user_session_cleanup_deleted");
                }
            }
        });
    }
    let user_shortcuts = Arc::new(
        api::infrastructure::db::repositories::user_shortcut_repository_sqlx::SqlxUserShortcutRepository::new(
            pool.clone(),
        ),
    );
    let user_shortcut_service =
        Arc::new(UserShortcutService::new(user_shortcuts.clone(), 32 * 1024));
    let git_repo = Arc::new(
        api::infrastructure::db::repositories::git_repository_sqlx::SqlxGitRepository::new(
            pool.clone(),
            cfg.encryption_key.clone(),
        ),
    );
    let git_pull_sessions = Arc::new(
        api::infrastructure::db::repositories::git_pull_session_repository_sqlx::GitPullSessionRepositorySqlx::new(
            pool.clone(),
        ),
    );
    let auto_archive_interval = Duration::from_secs(cfg.snapshot_archive_interval_secs);
    let mut local_hub: Option<api::infrastructure::realtime::Hub> = None;
    let (realtime_engine, snapshot_service_arc): (
        Arc<dyn api::application::ports::realtime_port::RealtimeEngine>,
        Arc<SnapshotService>,
    ) = if cfg.cluster_mode {
        tracing::info!("cluster_mode_enabled");
        let redis_settings = api::infrastructure::realtime::RedisRealtimeConfig {
            redis_url: cfg
                .redis_url
                .clone()
                .context("REDIS_URL must be set when CLUSTER_MODE=1")?,
            stream_prefix: cfg.redis_stream_prefix.clone(),
            stream_max_len: cfg.redis_stream_max_len,
            task_debounce_ms: cfg.redis_task_debounce_ms,
            min_message_lifetime_ms: cfg.redis_min_message_lifetime_ms,
            awareness_ttl_ms: cfg.redis_awareness_ttl_ms,
            snapshot_archive_interval_secs: cfg.snapshot_archive_interval_secs,
            spawn_persistence_worker: true,
        };
        let engine = Arc::new(
            api::infrastructure::realtime::RedisRealtimeEngine::from_config(
                redis_settings,
                pool.clone(),
                storage_resolver.clone(),
                storage_job_queue.clone(),
            )?,
        );
        let snapshot_service = engine.snapshot_service();
        let engine_trait: Arc<dyn api::application::ports::realtime_port::RealtimeEngine> =
            engine.clone();
        (engine_trait, snapshot_service)
    } else {
        tracing::info!("cluster_mode_disabled_using_local_hub");
        let doc_state_reader: Arc<
            dyn api::application::ports::realtime_hydration_port::DocStateReader,
        > = Arc::new(api::infrastructure::realtime::SqlxDocStateReader::new(
            pool.clone(),
        ));
        let backlog_reader: Arc<
            dyn api::application::ports::realtime_hydration_port::RealtimeBacklogReader,
        > = Arc::new(api::infrastructure::realtime::NoopBacklogReader::default());
        let doc_persistence: Arc<
            dyn api::application::ports::realtime_persistence_port::DocPersistencePort,
        > = Arc::new(api::infrastructure::realtime::SqlxDocPersistenceAdapter::new(pool.clone()));
        let linkgraph_repo: Arc<dyn api::application::ports::linkgraph_repository::LinkGraphRepository> =
            Arc::new(
                api::infrastructure::db::repositories::linkgraph_repository_sqlx::SqlxLinkGraphRepository::new(
                    pool.clone(),
                ),
            );
        let tagging_repo: Arc<dyn api::application::ports::tagging_repository::TaggingRepository> =
            Arc::new(
                api::infrastructure::db::repositories::tagging_repository_sqlx::SqlxTaggingRepository::new(
                    pool.clone(),
                ),
            );
        let hydration_service = Arc::new(
            api::application::services::realtime::doc_hydration::DocHydrationService::new(
                doc_state_reader.clone(),
                backlog_reader,
                storage_resolver.clone(),
            ),
        );
        let snapshot_service = Arc::new(
            api::application::services::realtime::snapshot::SnapshotService::new(
                doc_state_reader.clone(),
                doc_persistence.clone(),
                linkgraph_repo,
                tagging_repo,
                snapshot_archive_repo.clone(),
                storage_job_queue.clone(),
            ),
        );
        let hub = api::infrastructure::realtime::Hub::new(
            hydration_service,
            snapshot_service.clone(),
            doc_persistence,
            auto_archive_interval,
        );
        let engine =
            Arc::new(api::infrastructure::realtime::LocalRealtimeEngine { hub: hub.clone() });
        let engine_trait: Arc<dyn api::application::ports::realtime_port::RealtimeEngine> =
            engine.clone();
        local_hub = Some(hub);
        (engine_trait, snapshot_service)
    };

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
        if spawn_background_tasks {
            jobs.spawn("storage_projection_worker", async move {
                worker.run().await;
            });
        }
    }

    let git_storage_config = git_storage_driver_config(&cfg)?;
    let git_storage =
        api::infrastructure::git::storage::build_git_storage(git_storage_config).await?;
    let gitignore_port = Arc::new(api::infrastructure::storage::gitignore::FsGitignorePort);
    let git_workspace = Arc::new(
        api::infrastructure::git::workspace::GitWorkspaceService::new(
            pool.clone(),
            git_storage.clone(),
            storage_resolver.clone(),
            snapshot_service_arc.clone(),
            realtime_engine.clone(),
            document_repo.clone(),
        )?,
    );
    let git_service = Arc::new(GitService::new(
        git_repo.clone(),
        storage_resolver.clone(),
        files_repo.clone(),
        document_repo.clone(),
        gitignore_port.clone(),
        git_workspace.clone(),
        git_pull_sessions.clone(),
    ));
    if cfg.git_rebuild_enabled {
        let rebuild_service = Arc::new(GitRebuildService::new(
            git_rebuild_jobs.clone(),
            git_workspace.clone(),
            git_repo.clone(),
            metrics.clone(),
            workspace_permissions.clone(),
        ));
        if spawn_background_tasks {
            jobs.spawn("git_rebuild_worker", {
                let svc = rebuild_service.clone();
                async move {
                    svc.run().await;
                }
            });
        }
        let rebuild_scheduler = GitRebuildScheduler::new(
            git_rebuild_jobs.clone(),
            git_repo.clone(),
            git_workspace.clone(),
            Duration::from_secs(cfg.git_rebuild_interval_secs),
        );
        if spawn_background_tasks {
            jobs.spawn("git_rebuild_scheduler", async move {
                rebuild_scheduler.run().await;
            });
        }
    } else {
        tracing::info!("git_rebuild_scheduler_disabled");
    }
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
        if spawn_background_tasks {
            jobs.spawn("plugin_prefetch", async move {
                match installations.list_all().await {
                    Ok(installs) => {
                        for inst in installs.into_iter().filter(|i| i.status == "enabled") {
                            if let Err(err) = assets
                                .load_user_manifest(
                                    &inst.workspace_id,
                                    &inst.plugin_id,
                                    &inst.version,
                                )
                                .await
                            {
                                tracing::warn!(
                                    error = ?err,
                                    workspace_id = %inst.workspace_id,
                                    plugin = inst.plugin_id.as_str(),
                                    version = inst.version.as_str(),
                                    "prefetch_user_plugin_failed"
                                );
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(error = ?err, "list_all_plugin_installations_failed");
                    }
                }
            });
        }
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
        if spawn_background_tasks {
            jobs.spawn("storage_ingest_worker", async move {
                worker.run().await;
            });
        }
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

    let mut external_auth_providers: Vec<Arc<dyn ExternalAuthVerifier>> = Vec::new();
    if let Some(google_cfg) = cfg.google_oauth.clone() {
        match GoogleIdentityProvider::new(google_cfg.client_ids.clone()) {
            Ok(provider) => {
                tracing::info!("google_oauth_provider_enabled");
                external_auth_providers.push(Arc::new(provider));
            }
            Err(err) => {
                tracing::warn!(error = ?err, "google_oauth_provider_init_failed");
            }
        }
    }
    if let Some(github_cfg) = cfg.github_oauth.clone() {
        match GithubOAuthProvider::new(
            github_cfg.client_id.clone(),
            github_cfg.client_secret.clone(),
            github_cfg.redirect_uri.clone(),
        ) {
            Ok(provider) => {
                tracing::info!("github_oauth_provider_enabled");
                external_auth_providers.push(Arc::new(provider));
            }
            Err(err) => {
                tracing::warn!(error = ?err, "github_oauth_provider_init_failed");
            }
        }
    }
    if let Some(oidc_cfg) = cfg.oidc_oauth.clone() {
        match OidcIdentityProvider::discover(oidc_cfg).await {
            Ok(provider) => {
                tracing::info!("oidc_oauth_provider_enabled");
                external_auth_providers.push(Arc::new(provider));
            }
            Err(err) => {
                tracing::warn!(error = ?err, "oidc_oauth_provider_init_failed");
            }
        }
    }
    let external_auth_registry = Arc::new(ExternalAuthRegistry::new(external_auth_providers));

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
        auth_service.clone(),
        session_service.clone(),
        realtime_engine.clone(),
        storage_ingest_queue.clone(),
        external_auth_registry.clone(),
    );

    let presentation_cfg = PresentationConfig {
        frontend_url: cfg.frontend_url.clone(),
        upload_max_bytes: cfg.upload_max_bytes,
        public_base_url: cfg.public_base_url.clone(),
        session_cookie_secure: cookie_secure,
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
