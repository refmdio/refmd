use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::extract::MatchedPath;
use axum::{Router, routing::get};
use dotenvy::dotenv;
use http::HeaderValue;
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

use api::application::ports::plugin_asset_store::PluginAssetStore;
use api::application::ports::plugin_event_publisher::PluginEventPublisher;
use api::application::ports::plugin_installer::PluginInstaller;
use api::application::ports::plugin_runtime::PluginRuntime;
use api::bootstrap::app_context::{AppContext, AppServices};
use api::bootstrap::config::{Config, StorageBackend};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
        paths(
            api::presentation::http::auth::register,
            api::presentation::http::auth::login,
            api::presentation::http::auth::logout,
            api::presentation::http::auth::me,
            api::presentation::http::tags::list_tags,
            api::presentation::ws::axum_ws_entry,
            api::presentation::http::documents::list_documents,
            api::presentation::http::documents::create_document,
            api::presentation::http::documents::get_document,
            api::presentation::http::documents::update_document,
            api::presentation::http::documents::delete_document,
            api::presentation::http::documents::get_document_content,
            api::presentation::http::documents::download_document,
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
            api::presentation::http::shares::list_applicable_shares,
            api::presentation::http::shares::materialize_folder_share,
            api::presentation::http::public::publish_document,
            api::presentation::http::public::unpublish_document,
            api::presentation::http::public::get_publish_status,
            api::presentation::http::public::list_user_public_documents,
            api::presentation::http::public::get_public_by_owner_and_id,
            api::presentation::http::public::get_public_content_by_owner_and_id,
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
            api::presentation::http::markdown::render_markdown,
            api::presentation::http::markdown::render_markdown_many,
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
            api::presentation::http::og::public_document_og,
        ),
        components(schemas(
            api::presentation::http::auth::RegisterRequest,
            api::presentation::http::auth::LoginRequest,
            api::presentation::http::auth::LoginResponse,
            api::presentation::http::auth::UserResponse,
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
            api::presentation::http::shares::ShareItem,
            api::presentation::http::shares::ShareDocumentResponse,
            api::presentation::http::shares::ShareBrowseTreeItem,
            api::presentation::http::shares::ShareBrowseResponse,
            api::presentation::http::shares::ApplicableShareItem,
            api::presentation::http::shares::ActiveShareItem,
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
            api::presentation::http::git::GitDiffLineType,
            api::presentation::http::git::GitDiffLine,
            api::presentation::http::git::GitDiffResult,
            api::presentation::http::markdown::RenderOptionsPayload,
            api::presentation::http::markdown::PlaceholderItemPayload,
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
            (name = "OpenGraph", description = "Public metadata endpoints for social previews")
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

    let storage_port: Arc<dyn api::application::ports::storage_port::StoragePort> =
        match cfg.storage_backend {
            StorageBackend::Filesystem => {
                Arc::new(api::infrastructure::storage::port_impl::FsStoragePort {
                    pool: pool.clone(),
                    uploads_root: std::path::PathBuf::from(&cfg.storage_root),
                })
            }
            StorageBackend::S3 => Arc::new(
                api::infrastructure::storage::s3::S3StoragePort::new(pool.clone(), &cfg).await?,
            ),
        };

    // Build Realtime Hub
    let hub = api::infrastructure::realtime::Hub::new(pool.clone(), storage_port.clone());
    let document_repo = Arc::new(
        api::infrastructure::db::repositories::document_repository_sqlx::SqlxDocumentRepository::new(
            pool.clone(),
        ),
    );
    let shares_repo_impl = Arc::new(
        api::infrastructure::db::repositories::shares_repository_sqlx::SqlxSharesRepository::new(
            pool.clone(),
        ),
    );
    let access_repo = Arc::new(
        api::infrastructure::db::repositories::access_repository_sqlx::SqlxAccessRepository::new(
            pool.clone(),
        ),
    );
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
    let tag_repo = Arc::new(
        api::infrastructure::db::repositories::tag_repository_sqlx::SqlxTagRepository::new(
            pool.clone(),
        ),
    );
    let git_repo = Arc::new(
        api::infrastructure::db::repositories::git_repository_sqlx::SqlxGitRepository::new(
            pool.clone(),
            cfg.encryption_key.clone(),
        ),
    );
    let git_storage = api::infrastructure::git::storage::build_git_storage(&cfg).await?;
    let gitignore_port = Arc::new(api::infrastructure::storage::gitignore::FsGitignorePort);
    let git_workspace = Arc::new(
        api::infrastructure::git::workspace::GitWorkspaceService::new(
            pool.clone(),
            git_storage.clone(),
            storage_port.clone(),
        )?,
    );
    let realtime_engine: Arc<dyn api::application::ports::realtime_port::RealtimeEngine> =
        if cfg.cluster_mode {
            tracing::info!("cluster_mode_enabled");
            Arc::new(
                api::infrastructure::realtime::RedisRealtimeEngine::from_config(
                    &cfg,
                    pool.clone(),
                    storage_port.clone(),
                )?,
            )
        } else {
            tracing::info!("cluster_mode_disabled_using_local_hub");
            Arc::new(api::infrastructure::realtime::LocalRealtimeEngine { hub: hub.clone() })
        };
    let plugin_repo = Arc::new(
        api::infrastructure::db::repositories::plugin_repository_sqlx::SqlxPluginRepository::new(
            pool.clone(),
        ),
    );
    let plugin_installations = Arc::new(
        api::infrastructure::db::repositories::plugin_installation_repository_sqlx::SqlxPluginInstallationRepository::new(
            pool.clone(),
        ),
    );
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
                )?,
            );
            let runtime: Arc<dyn PluginRuntime> = store.clone();
            let installer: Arc<dyn PluginInstaller> = store.clone();
            let assets: Arc<dyn PluginAssetStore> = store.clone();
            (runtime, installer, assets)
        }
        StorageBackend::S3 => {
            let store = Arc::new(
                api::infrastructure::plugins::s3_store::S3BackedPluginStore::new(
                    &cfg.plugin_dir,
                    &cfg,
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
    let plugin_fetcher = Arc::new(
        api::infrastructure::plugins::package_fetcher_reqwest::ReqwestPluginPackageFetcher::new(),
    );
    let plugin_event_bus = Arc::new(
        api::infrastructure::plugins::event_bus_pg::PgPluginEventBus::new(
            pool.clone(),
            "plugin_events",
        ),
    );
    if let Some(store) = &s3_plugin_store {
        store.spawn_event_listener(plugin_event_bus.clone());
    }
    let plugin_event_publisher: Arc<dyn PluginEventPublisher> = plugin_event_bus.clone();

    let services = AppServices::new(
        document_repo,
        shares_repo_impl.clone(),
        shares_repo_impl,
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
        realtime_engine.clone(),
        plugin_repo,
        plugin_installations,
        plugin_runtime.clone(),
        plugin_installer.clone(),
        plugin_fetcher,
        plugin_event_bus.clone(),
        plugin_event_publisher,
        plugin_assets.clone(),
    );

    let ctx = AppContext::new(cfg.clone(), services);

    // Build CORS
    let cors = if let Some(origin) = cfg.frontend_url.clone() {
        match HeaderValue::from_str(&origin) {
            Ok(v) => CorsLayer::new()
                .allow_origin(v)
                .allow_methods([
                    http::Method::GET,
                    http::Method::POST,
                    http::Method::PUT,
                    http::Method::DELETE,
                    http::Method::PATCH,
                    http::Method::OPTIONS,
                ])
                .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
                .allow_credentials(true),
            Err(_) => CorsLayer::new()
                .allow_origin(AllowOrigin::mirror_request())
                .allow_methods([
                    http::Method::GET,
                    http::Method::POST,
                    http::Method::PUT,
                    http::Method::DELETE,
                    http::Method::PATCH,
                    http::Method::OPTIONS,
                ])
                .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
                .allow_credentials(true),
        }
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
                .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
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
                .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
                .allow_credentials(true)
        }
    };

    // Ensure uploads dir exists
    if matches!(cfg.storage_backend, StorageBackend::Filesystem) {
        if let Err(e) = tokio::fs::create_dir_all(&cfg.storage_root).await {
            tracing::warn!(error=?e, dir=%cfg.storage_root, "Failed to create uploads dir");
        }
    }

    // Build upload router with state
    let upload_router = Router::new()
        .route("/*path", get(api::presentation::http::files::serve_upload))
        .with_state(ctx.clone());

    let plugin_root = {
        let candidates = [
            std::path::PathBuf::from("./plugins"),
            std::path::PathBuf::from("../plugins"),
        ];
        candidates
            .iter()
            .find(|p| p.exists())
            .cloned()
            .unwrap_or_else(|| std::path::PathBuf::from("./plugins"))
    };

    // Build API router
    let api_router = Router::new()
        .nest(
            "/api",
            api::presentation::http::health::routes(pool.clone()),
        )
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
            "/api/public",
            api::presentation::http::public::routes(ctx.clone()),
        )
        .nest("/api/og", api::presentation::http::og::routes(ctx.clone()))
        .nest_service("/api/plugin-assets", ServeDir::new(plugin_root))
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
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

    let api_router = api_router.nest("/api/uploads", upload_router);

    // Mount WS endpoint on the same port as HTTP

    // Compose final app for HTTP
    let api_addr = SocketAddr::from(([0, 0, 0, 0], cfg.api_port));
    info!(%api_addr, "HTTP API listening");
    let listener = tokio::net::TcpListener::bind(api_addr).await?;
    let ws_router = Router::new()
        .route("/api/yjs/:id", get(api::presentation::ws::axum_ws_entry))
        .with_state(ctx.clone());

    let app = api_router.merge(ws_router);

    let api_handle: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        axum::serve(listener, app).await?;
        Ok(())
    });

    // Background snapshots
    let snap_handle: Option<JoinHandle<anyhow::Result<()>>> = if cfg.cluster_mode {
        None
    } else {
        let hub_for_snap = hub.clone();
        let cfg_for_snap = cfg.clone();
        Some(tokio::spawn(async move {
            let interval = Duration::from_secs(cfg_for_snap.snapshot_interval_secs);
            loop {
                if let Err(e) = hub_for_snap
                    .snapshot_all(
                        cfg_for_snap.snapshot_keep_versions,
                        cfg_for_snap.updates_keep_window,
                    )
                    .await
                {
                    tracing::error!(error = ?e, "snapshot_loop_failed");
                }
                sleep(interval).await;
            }
        }))
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
