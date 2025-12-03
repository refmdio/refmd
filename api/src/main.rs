use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::DefaultBodyLimit;
use axum::extract::MatchedPath;
use axum::{Router, middleware, routing::get};
use chrono::Utc;
use dotenvy::dotenv;
use http::HeaderValue;
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};

use api::application::ports::doc_event_log::DocEventLog;
use api::application::ports::git_rebuild_job_queue::GitRebuildJobQueue;
use api::application::ports::plugin_asset_store::PluginAssetStore;
use api::application::ports::plugin_event_publisher::PluginEventPublisher;
use api::application::ports::plugin_event_subscriber::PluginEventSubscriber;
use api::application::ports::plugin_installation_repository::PluginInstallationRepository;
use api::application::ports::plugin_installer::PluginInstaller;
use api::application::ports::plugin_package_fetcher::PluginPackageFetcher;
use api::application::ports::plugin_runtime::PluginRuntime;
use api::application::ports::storage_ingest_queue::StorageIngestQueue;
use api::application::ports::storage_port::{StorageProjectionPort, StorageResolverPort};
use api::application::ports::storage_projection_queue::StorageProjectionQueue;
use api::application::ports::storage_reconcile_backend::StorageReconcileBackend;
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
use api::infrastructure::auth::github::GithubOAuthProvider;
use api::infrastructure::auth::google::GoogleIdentityProvider;
use api::infrastructure::auth::oidc::OidcIdentityProvider;
use api::infrastructure::db::advisory_lock::AdvisoryLock;
use api::infrastructure::documents::doc_event_log::PgDocEventLog;
use api::infrastructure::documents::event_poller::DocEventPoller;
use api::infrastructure::documents::exporter::DefaultDocumentExporter;
use api::infrastructure::documents::git_dirty_subscriber::GitDirtyDocEventSubscriber;
use api::infrastructure::git::PgGitRebuildJobQueue;
use api::infrastructure::plugins::filesystem_store::PluginExecutionLimits;
use api::infrastructure::storage::{
    FsIngestWatcher, FsReconcileBackend, PgStorageIngestQueue, PgStorageProjectionQueue,
    PgStorageReconcileJobs, S3ReconcileBackend, StorageConsistencyMonitor, StorageIngestWorker,
    StorageProjectionWorker,
};
use api::presentation::context::{AppContext, AppServices, PresentationConfig};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

const SESSION_CLEANUP_INTERVAL_SECS: u64 = 15 * 60;
const SESSION_CLEANUP_BATCH_SIZE: i64 = 500;

#[derive(OpenApi)]
#[openapi(
        paths(
            api::presentation::http::auth::register,
            api::presentation::http::auth::login,
            api::presentation::http::auth::oauth_state,
            api::presentation::http::auth::oauth_login,
            api::presentation::http::auth::list_oauth_providers,
            api::presentation::http::auth::refresh_session,
            api::presentation::http::auth::logout,
            api::presentation::http::auth::me,
            api::presentation::http::auth::list_sessions,
            api::presentation::http::auth::revoke_session,
            api::presentation::http::api_tokens::list_api_tokens,
            api::presentation::http::api_tokens::create_api_token,
            api::presentation::http::api_tokens::revoke_api_token,
            api::presentation::http::shortcuts::get_user_shortcuts,
            api::presentation::http::shortcuts::update_user_shortcuts,
            api::presentation::http::tags::list_tags,
            api::presentation::ws::axum_ws_entry,
            api::presentation::http::documents::list_documents,
            api::presentation::http::documents::create_document,
            api::presentation::http::documents::get_document,
            api::presentation::http::documents::update_document,
            api::presentation::http::documents::delete_document,
            api::presentation::http::documents::get_document_content,
            api::presentation::http::documents::download_document,
            api::presentation::http::documents::list_document_snapshots,
            api::presentation::http::documents::get_document_snapshot_diff,
            api::presentation::http::documents::restore_document_snapshot,
            api::presentation::http::documents::download_document_snapshot,
            api::presentation::http::documents::search_documents,
            api::presentation::http::documents::get_backlinks,
            api::presentation::http::documents::get_outgoing_links,
            api::presentation::http::files::upload_file,
            api::presentation::http::files::get_file,
            api::presentation::http::files::get_file_by_name,
            api::presentation::http::shares::create_share,
            api::presentation::http::shares::delete_share,
            api::presentation::http::shares::list_document_shares,
            api::presentation::http::shares::validate_share_token,
            api::presentation::http::shares::browse_share,
            api::presentation::http::shares::list_active_shares,
            api::presentation::http::shares::create_share_mount,
            api::presentation::http::shares::list_share_mounts,
            api::presentation::http::shares::delete_share_mount,
            api::presentation::http::shares::list_applicable_shares,
            api::presentation::http::shares::materialize_folder_share,
            api::presentation::http::public::publish_document,
            api::presentation::http::public::unpublish_document,
            api::presentation::http::public::get_publish_status,
            api::presentation::http::public::list_workspace_public_documents,
            api::presentation::http::public::get_public_by_workspace_and_id,
            api::presentation::http::public::get_public_content_by_workspace_and_id,
            api::presentation::http::git::get_config,
            api::presentation::http::git::create_or_update_config,
            api::presentation::http::git::delete_config,
            api::presentation::http::git::get_status,
            api::presentation::http::git::get_changes,
            api::presentation::http::git::get_history,
            api::presentation::http::git::get_working_diff,
            api::presentation::http::git::get_commit_diff,
            api::presentation::http::git::sync_now,
            api::presentation::http::git::init_repository,
            api::presentation::http::git::deinit_repository,
            api::presentation::http::git::ignore_document,
            api::presentation::http::git::ignore_folder,
            api::presentation::http::git::get_gitignore_patterns,
            api::presentation::http::git::add_gitignore_patterns,
            api::presentation::http::git::check_path_ignored,
            api::presentation::http::storage_ingest::enqueue_ingest_events,
            api::presentation::http::markdown::render_markdown,
            api::presentation::http::markdown::render_markdown_many,
            api::presentation::http::workspaces::list_workspaces,
            api::presentation::http::workspaces::create_workspace,
            api::presentation::http::workspaces::switch_workspace,
            api::presentation::http::workspaces::list_members,
            api::presentation::http::workspaces::update_member_role,
            api::presentation::http::workspaces::get_workspace_permissions,
            api::presentation::http::workspaces::list_roles,
            api::presentation::http::workspaces::create_role,
            api::presentation::http::workspaces::update_role,
            api::presentation::http::workspaces::delete_role,
            api::presentation::http::workspaces::list_invitations,
            api::presentation::http::workspaces::create_invitation,
            api::presentation::http::workspaces::accept_invitation,
            api::presentation::http::workspaces::download_workspace_archive,
            api::presentation::http::plugins::get_manifest,
            api::presentation::http::plugins::exec_action,
            api::presentation::http::plugins::list_records,
            api::presentation::http::plugins::create_record,
            api::presentation::http::plugins::update_record,
            api::presentation::http::plugins::delete_record,
            api::presentation::http::plugins::get_kv_value,
            api::presentation::http::plugins::put_kv_value,
            api::presentation::http::plugins::install_from_url,
            api::presentation::http::plugins::uninstall,
            api::presentation::http::plugins::sse_updates,
            api::presentation::http::health::health,
        ),
        components(schemas(
            api::presentation::http::auth::RegisterRequest,
            api::presentation::http::auth::LoginRequest,
            api::presentation::http::auth::LoginResponse,
            api::presentation::http::auth::OAuthLoginRequest,
            api::presentation::http::auth::OAuthStateResponse,
            api::presentation::http::auth::UserResponse,
            api::presentation::http::auth::WorkspaceMembershipResponse,
            api::presentation::http::api_tokens::ApiTokenItem,
            api::presentation::http::api_tokens::ApiTokenCreateRequest,
            api::presentation::http::api_tokens::ApiTokenCreateResponse,
            api::presentation::http::tags::TagItem,
            api::presentation::http::documents::Document,
            api::presentation::http::documents::DocumentListResponse,
            api::presentation::http::documents::CreateDocumentRequest,
            api::presentation::http::documents::UpdateDocumentRequest,
            api::presentation::http::documents::BacklinkInfo,
            api::presentation::http::documents::BacklinksResponse,
            api::presentation::http::documents::OutgoingLink,
            api::presentation::http::documents::OutgoingLinksResponse,
            api::presentation::http::documents::SearchResult,
            api::presentation::http::files::UploadFileResponse,
            api::presentation::http::files::UploadFileMultipart,
            api::presentation::http::shares::CreateShareRequest,
            api::presentation::http::shares::CreateShareResponse,
            api::presentation::http::shares::CreateShareMountRequest,
            api::presentation::http::shares::ShareItem,
            api::presentation::http::shares::ShareDocumentResponse,
            api::presentation::http::shares::ShareBrowseTreeItem,
            api::presentation::http::shares::ShareBrowseResponse,
            api::presentation::http::shares::ApplicableShareItem,
            api::presentation::http::shares::ActiveShareItem,
            api::presentation::http::shares::ShareMountItem,
            api::presentation::http::shares::MaterializeResponse,
            api::presentation::http::public::PublishResponse,
            api::presentation::http::public::PublicDocumentSummary,
            api::presentation::http::git::GitConfigResponse,
            api::presentation::http::git::CreateGitConfigRequest,
            api::presentation::http::git::UpdateGitConfigRequest,
            api::presentation::http::git::GitStatus,
            api::presentation::http::git::GitSyncRequest,
            api::presentation::http::git::GitSyncResponse,
            api::presentation::http::git::GitChangeItem,
            api::presentation::http::git::GitChangesResponse,
            api::presentation::http::git::GitCommitItem,
            api::presentation::http::git::GitHistoryResponse,
            api::presentation::http::git::AddPatternsRequest,
            api::presentation::http::git::CheckIgnoredRequest,
            api::application::dto::diff::TextDiffLineType,
            api::application::dto::diff::TextDiffLine,
            api::application::dto::diff::TextDiffResult,
            api::presentation::http::markdown::RenderOptionsPayload,
            api::presentation::http::markdown::PlaceholderItemPayload,
            api::presentation::http::workspaces::WorkspaceResponse,
            api::presentation::http::workspaces::CreateWorkspaceRequest,
            api::presentation::http::workspaces::WorkspaceMemberResponse,
            api::presentation::http::workspaces::UpdateMemberRoleRequest,
            api::presentation::http::workspaces::WorkspaceRoleResponse,
            api::presentation::http::workspaces::PermissionOverridePayload,
            api::presentation::http::workspaces::CreateWorkspaceRoleRequest,
            api::presentation::http::workspaces::UpdateWorkspaceRoleRequest,
            api::presentation::http::workspaces::SwitchWorkspaceResponse,
            api::presentation::http::workspaces::WorkspacePermissionsResponse,
            api::presentation::http::workspaces::WorkspaceInvitationResponse,
            api::presentation::http::workspaces::CreateWorkspaceInvitationRequest,
            api::presentation::http::workspaces::CreateWorkspaceRequest,
            api::presentation::http::markdown::RenderResponseBody,
            api::presentation::http::markdown::RenderRequest,
            api::presentation::http::markdown::RenderManyRequest,
            api::presentation::http::markdown::RenderManyResponse,
            api::presentation::http::plugins::ManifestItem,
            api::presentation::http::plugins::RecordsResponse,
            api::presentation::http::plugins::CreateRecordBody,
            api::presentation::http::plugins::UpdateRecordBody,
            api::presentation::http::plugins::KvValueResponse,
            api::presentation::http::plugins::KvValueBody,
            api::presentation::http::plugins::ExecBody,
            api::presentation::http::plugins::ExecResultResponse,
            api::presentation::http::plugins::InstallFromUrlBody,
            api::presentation::http::plugins::InstallResponse,
            api::presentation::http::plugins::UninstallBody,
            api::presentation::http::health::HealthResp,
            api::presentation::http::shortcuts::UserShortcutResponse,
            api::presentation::http::shortcuts::UpdateUserShortcutRequest,
        )),
        tags(
            (name = "Auth", description = "Authentication"),
            (name = "Documents", description = "Documents management"),
            (name = "Files", description = "File management"),
            (name = "Sharing", description = "Document sharing"),
            (name = "Public Documents", description = "Public pages"),
            (name = "Git", description = "Git integration"),
            (name = "Markdown", description = "Markdown rendering"),
            (name = "Plugins", description = "Plugins management & data APIs"),
            (name = "Health", description = "System health checks"),
        )
    )]
struct ApiDoc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "api=debug,warp=info,axum=info,tower_http=info".into()),
        )
        .init();

    let cfg = Config::from_env()?;
    info!(?cfg, "Starting RefMD backend");

    // Database
    let pool = api::infrastructure::db::connect_pool(&cfg.database_url).await?;
    api::infrastructure::db::migrate(&pool).await?;

    let asset_signer = Arc::new(AssetSigner::new(&cfg.plugin_asset_sign_key));

    let uploads_root = std::path::PathBuf::from(&cfg.storage_root);
    let (storage_resolver, storage_projection, reconcile_backend, reconcile_ingest_known_paths): (
        Arc<dyn StorageResolverPort>,
        Arc<dyn StorageProjectionPort>,
        Arc<dyn StorageReconcileBackend>,
        bool,
    ) = match cfg.storage_backend {
        StorageBackend::Filesystem => {
            let port = Arc::new(api::infrastructure::storage::port_impl::FsStoragePort {
                pool: pool.clone(),
                uploads_root: uploads_root.clone(),
            });
            let backend = FsReconcileBackend::new(uploads_root.clone());
            (port.clone(), port, backend, false)
        }
        StorageBackend::S3 => {
            let s3_settings = api::infrastructure::storage::s3::S3StorageConfig {
                uploads_root: uploads_root.clone(),
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
            let port = Arc::new(
                api::infrastructure::storage::s3::S3StoragePort::new(pool.clone(), &s3_settings)
                    .await?,
            );
            let backend = S3ReconcileBackend::new(&s3_settings).await?;
            (port.clone(), port, backend, true)
        }
    };

    let storage_job_queue: Arc<dyn StorageProjectionQueue> =
        Arc::new(PgStorageProjectionQueue::new(pool.clone()));
    let storage_ingest_queue: Arc<dyn StorageIngestQueue> =
        Arc::new(PgStorageIngestQueue::new(pool.clone()));

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
        tokio::spawn(monitor.run());
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
        tokio::spawn(async move {
            watcher.run().await;
        });
    }
    {
        let poller = Arc::new(DocEventPoller::new(
            pool.clone(),
            doc_event_subscriber.clone(),
            Duration::from_millis(500),
            200,
            "doc_event_poller",
        ));
        tokio::spawn(async move {
            poller.run().await;
        });
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
        tokio::spawn({
            let svc = reconcile_service.clone();
            async move {
                svc.run().await;
            }
        });
        let scheduler = StorageReconcileScheduler::new(
            storage_reconcile_jobs.clone(),
            workspace_repo.clone(),
            Duration::from_secs(60 * 60),
        );
        tokio::spawn(async move {
            scheduler.run().await;
        });
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

    {
        let repo = user_session_repo.clone();
        tokio::spawn(async move {
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
        tokio::spawn(async move {
            worker.run().await;
        });
    }

    let git_storage_config = match cfg.storage_backend {
        StorageBackend::Filesystem => {
            api::infrastructure::git::storage::GitStorageDriverConfig::Filesystem {
                root: uploads_root.clone(),
            }
        }
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
            api::infrastructure::git::storage::GitStorageDriverConfig::S3(s3_settings)
        }
    };
    let git_storage =
        api::infrastructure::git::storage::build_git_storage(git_storage_config).await?;
    let gitignore_port = Arc::new(api::infrastructure::storage::gitignore::FsGitignorePort);
    let git_workspace = Arc::new(
        api::infrastructure::git::workspace::GitWorkspaceService::new(
            pool.clone(),
            git_storage.clone(),
            storage_resolver.clone(),
            snapshot_service_arc.clone(),
        )?,
    );
    let git_service = Arc::new(GitService::new(
        git_repo.clone(),
        storage_resolver.clone(),
        files_repo.clone(),
        document_repo.clone(),
        gitignore_port.clone(),
        git_workspace.clone(),
    ));
    if cfg.git_rebuild_enabled {
        let rebuild_service = Arc::new(GitRebuildService::new(
            git_rebuild_jobs.clone(),
            git_workspace.clone(),
            git_repo.clone(),
            metrics.clone(),
            workspace_permissions.clone(),
        ));
        tokio::spawn({
            let svc = rebuild_service.clone();
            async move {
                svc.run().await;
            }
        });
        let rebuild_scheduler = GitRebuildScheduler::new(
            git_rebuild_jobs.clone(),
            git_repo.clone(),
            git_workspace.clone(),
            Duration::from_secs(cfg.git_rebuild_interval_secs),
        );
        tokio::spawn(async move {
            rebuild_scheduler.run().await;
        });
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
    let plugin_limits = {
        let timeout = if cfg.plugin_timeout_secs == 0 {
            None
        } else {
            Some(std::time::Duration::from_secs(cfg.plugin_timeout_secs))
        };
        let memory_pages_raw = cfg.plugin_memory_max_mb.saturating_mul(16);
        let memory_max_pages = if memory_pages_raw == 0 {
            None
        } else {
            Some(memory_pages_raw.min(u32::MAX as u64) as u32)
        };
        let fuel_limit = cfg
            .plugin_fuel_limit
            .and_then(|limit| if limit == 0 { None } else { Some(limit) });
        PluginExecutionLimits::new(timeout, memory_max_pages, fuel_limit)
    };
    let mut s3_plugin_store: Option<
        Arc<api::infrastructure::plugins::s3_store::S3BackedPluginStore>,
    > = None;
    let (plugin_runtime, plugin_installer, plugin_assets): (
        Arc<dyn PluginRuntime>,
        Arc<dyn PluginInstaller>,
        Arc<dyn PluginAssetStore>,
    ) = match cfg.storage_backend {
        StorageBackend::Filesystem => {
            let store = Arc::new(
                api::infrastructure::plugins::filesystem_store::FilesystemPluginStore::new(
                    &cfg.plugin_dir,
                    plugin_limits,
                )?,
            );
            let runtime: Arc<dyn PluginRuntime> = store.clone();
            let installer: Arc<dyn PluginInstaller> = store.clone();
            let assets: Arc<dyn PluginAssetStore> = store.clone();
            (runtime, installer, assets)
        }
        StorageBackend::S3 => {
            let s3_store_cfg = api::infrastructure::plugins::s3_store::S3PluginStoreConfig {
                plugin_dir: cfg.plugin_dir.clone(),
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
            let store = Arc::new(
                api::infrastructure::plugins::s3_store::S3BackedPluginStore::new(
                    &s3_store_cfg,
                    plugin_limits,
                )
                .await?,
            );
            s3_plugin_store = Some(store.clone());
            let runtime: Arc<dyn PluginRuntime> = store.clone();
            let installer: Arc<dyn PluginInstaller> = store.clone();
            let assets: Arc<dyn PluginAssetStore> = store.clone();
            (runtime, installer, assets)
        }
    };
    let plugin_permission_service = Arc::new(PluginPermissionService::new(plugin_runtime.clone()));
    let plugin_fetcher: Arc<dyn PluginPackageFetcher> = Arc::new(
        api::infrastructure::plugins::package_fetcher_reqwest::ReqwestPluginPackageFetcher::new(),
    );
    let plugin_execution_service = Arc::new(PluginExecutionService::new(
        plugin_repo.clone(),
        document_repo.clone(),
        plugin_runtime.clone(),
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
        tokio::spawn(async move {
            match installations.list_all().await {
                Ok(installs) => {
                    for inst in installs.into_iter().filter(|i| i.status == "enabled") {
                        if let Err(err) = assets
                            .load_user_manifest(&inst.workspace_id, &inst.plugin_id, &inst.version)
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
        tokio::spawn(async move {
            worker.run().await;
        });
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

    let frontend_origin = if let Some(origin) = cfg.frontend_url.clone() {
        Some(HeaderValue::from_str(&origin).map_err(|_| {
            anyhow::anyhow!(
                "FRONTEND_URL must be a valid origin (e.g., https://app.example.com)"
            )
        })?)
    } else {
        None
    };

    // Build CORS
    let cors_allow_headers = [
        http::header::CONTENT_TYPE,
        http::header::AUTHORIZATION,
        http::header::HeaderName::from_static("x-workspace-id"),
    ];
    let cors_expose_headers = [http::header::WWW_AUTHENTICATE];
    let cors = if let Some(origin) = frontend_origin.clone() {
        CorsLayer::new()
            .allow_origin(origin)
            .allow_methods([
                http::Method::GET,
                http::Method::POST,
                http::Method::PUT,
                http::Method::DELETE,
                http::Method::PATCH,
                http::Method::OPTIONS,
            ])
            .allow_headers(cors_allow_headers.clone())
            .expose_headers(cors_expose_headers.clone())
            .allow_credentials(true)
    } else {
        if cfg.is_production {
            // In production, FRONTEND_URL is mandatory (enforced earlier), but fallback defensively to deny all
            CorsLayer::new()
                .allow_origin(AllowOrigin::exact(HeaderValue::from_static(
                    "http://invalid",
                )))
                .allow_methods([
                    http::Method::GET,
                    http::Method::POST,
                    http::Method::PUT,
                    http::Method::DELETE,
                    http::Method::PATCH,
                    http::Method::OPTIONS,
                ])
                .allow_headers(cors_allow_headers.clone())
                .expose_headers(cors_expose_headers.clone())
        } else {
            // Development convenience
            CorsLayer::new()
                .allow_origin(AllowOrigin::mirror_request())
                .allow_methods([
                    http::Method::GET,
                    http::Method::POST,
                    http::Method::PUT,
                    http::Method::DELETE,
                    http::Method::PATCH,
                    http::Method::OPTIONS,
                ])
                .allow_headers(cors_allow_headers.clone())
                .expose_headers(cors_expose_headers.clone())
                .allow_credentials(true)
        }
    };

    // Ensure uploads dir exists even when using S3 backend (local staging is still required)
    if let Err(e) = tokio::fs::create_dir_all(&cfg.storage_root).await {
        tracing::warn!(error=?e, dir=%cfg.storage_root, "Failed to create uploads dir");
    }

    // Build upload router with state
    let upload_router = Router::new()
        .route("/*path", get(api::presentation::http::files::serve_upload))
        .with_state(ctx.clone());

    // Build API router
    let api_router = Router::new()
        .nest("/api", api::presentation::http::health::routes(ctx.clone()))
        .nest(
            "/api",
            api::presentation::http::documents::routes(ctx.clone()),
        )
        .nest(
            "/api/auth",
            api::presentation::http::auth::routes(ctx.clone()),
        )
        .nest("/api", api::presentation::http::shares::routes(ctx.clone()))
        .nest("/api", api::presentation::http::files::routes(ctx.clone()))
        .nest("/api", api::presentation::http::tags::routes(ctx.clone()))
        .nest("/api", api::presentation::http::git::routes(ctx.clone()))
        .nest(
            "/api",
            api::presentation::http::markdown::routes(ctx.clone()),
        )
        .nest(
            "/api",
            api::presentation::http::plugins::routes(ctx.clone()),
        )
        .nest(
            "/api",
            api::presentation::http::api_tokens::routes(ctx.clone()),
        )
        .nest(
            "/api",
            api::presentation::http::storage_ingest::routes(ctx.clone()),
        )
        .nest(
            "/api",
            api::presentation::http::workspaces::routes(ctx.clone()),
        )
        .nest(
            "/api",
            api::presentation::http::shortcuts::routes(ctx.clone()),
        )
        .nest(
            "/api/public",
            api::presentation::http::public::routes(ctx.clone()),
        )
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            api::presentation::http::auth::refresh_middleware,
        ))
        .layer(middleware::from_fn(
            api::presentation::http::auth::request_status::middleware,
        ))
        .layer(cors)
        // Global body size limit for uploads (configurable)
        .layer(DefaultBodyLimit::max(cfg.upload_max_bytes))
        .layer(
            TraceLayer::new_for_http().make_span_with(|req: &http::Request<_>| {
                let method = req.method().clone();
                let uri = req.uri().clone();
                let matched = req
                    .extensions()
                    .get::<MatchedPath>()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                tracing::info_span!("http", %method, %uri, matched_path = %matched)
            }),
        );

    let metrics_router = Router::new()
        .route(
            "/metrics",
            get(api::presentation::http::metrics::metrics_handler),
        )
        .with_state(ctx.clone());
    let api_router = api_router.merge(metrics_router);

    let api_router = api_router.nest("/api/uploads", upload_router);

    // Mount WS endpoint on the same port as HTTP

    // Compose final app for HTTP
    let api_addr = SocketAddr::from(([0, 0, 0, 0], cfg.api_port));
    info!(%api_addr, "HTTP API listening");
    let listener = tokio::net::TcpListener::bind(api_addr).await?;
    let ws_router = Router::new()
        .route("/api/yjs/:id", get(api::presentation::ws::axum_ws_entry))
        .with_state(ctx.clone())
        .layer(middleware::from_fn_with_state(
            ctx.clone(),
            api::presentation::http::auth::refresh_middleware,
        ))
        .layer(middleware::from_fn(
            api::presentation::http::auth::request_status::middleware,
        ));

    let app = api_router.merge(ws_router);

    let api_handle: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        axum::serve(listener, app).await?;
        Ok(())
    });

    // Background snapshots
    const SNAPSHOT_LOCK_KEY: i64 = i64::from_be_bytes(*b"REFSNAP1");

    let snap_handle: Option<JoinHandle<anyhow::Result<()>>> =
        if let Some(hub_for_snap) = local_hub.clone() {
            let cfg_for_snap = cfg.clone();
            let pool_for_snap = pool.clone();
            Some(tokio::spawn(async move {
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
            }))
        } else {
            None
        };

    match api_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!(?e, "API server task failed"),
        Err(e) => error!(?e, "API server task panicked"),
    }

    if let Some(handle) = snap_handle {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(?e, "Snapshot task failed"),
            Err(e) => error!(?e, "Snapshot task panicked"),
        }
    }
    Ok(())
}
