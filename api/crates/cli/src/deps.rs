use std::sync::Arc;

use anyhow::Result;

use bootstrap::app::AppBuilder;
use bootstrap::application::core::ports::storage::storage_ingest_queue::StorageIngestQueue;
use bootstrap::application::core::ports::storage::storage_projection_queue::StorageProjectionQueue;
use bootstrap::application::core::ports::storage::storage_reconcile_jobs::StorageReconcileJobs;
use bootstrap::application::plugins::ports::plugin_asset_store::PluginAssetStore;
use bootstrap::application::workspaces::services::WorkspaceServiceFacade;
use bootstrap::config::Config;
use bootstrap::infrastructure::core::db::PgPool;
use bootstrap::infrastructure::documents::db::repositories::document_repository_sqlx::SqlxDocumentRepository;
use bootstrap::infrastructure::documents::db::repositories::files_repository_sqlx::SqlxFilesRepository;
use bootstrap::infrastructure::documents::db::repositories::shares_repository_sqlx::SqlxSharesRepository;
use bootstrap::infrastructure::identity::db::repositories::api_token_repository_sqlx::SqlxApiTokenRepository;
use bootstrap::infrastructure::identity::db::repositories::user_repository_sqlx::SqlxUserRepository;
use bootstrap::infrastructure::identity::db::repositories::user_session_repository_sqlx::SqlxUserSessionRepository;
use bootstrap::infrastructure::plugins::db::repositories::plugin_installation_repository_sqlx::SqlxPluginInstallationRepository;
use bootstrap::infrastructure::plugins::db::repositories::plugin_repository_sqlx::SqlxPluginRepository;

pub(crate) struct Deps {
    pub(crate) pool: PgPool,
    pub(crate) user_repo: SqlxUserRepository,
    pub(crate) workspace_service: Arc<dyn WorkspaceServiceFacade>,
    pub(crate) ingest_queue: Arc<dyn StorageIngestQueue>,
    pub(crate) reconcile_jobs: Arc<dyn StorageReconcileJobs>,
    pub(crate) session_repo: SqlxUserSessionRepository,
    pub(crate) document_repo: SqlxDocumentRepository,
    pub(crate) files_repo: SqlxFilesRepository,
    pub(crate) plugin_installations: SqlxPluginInstallationRepository,
    pub(crate) plugin_repo: SqlxPluginRepository,
    pub(crate) api_tokens: SqlxApiTokenRepository,
    pub(crate) shares_repo: SqlxSharesRepository,
    pub(crate) plugin_assets: Arc<dyn PluginAssetStore>,
    pub(crate) git_repo:
        bootstrap::infrastructure::git::db::repositories::git_repository_sqlx::SqlxGitRepository,
    pub(crate) storage_jobs: Arc<dyn StorageProjectionQueue>,
}

pub(crate) async fn build(database_url: Option<String>) -> Result<Deps> {
    let mut cfg = Config::from_env()?;
    if let Some(db_url) = database_url {
        cfg.database_url = db_url;
    }

    let runtime = AppBuilder::new(cfg.clone())
        .with_background_tasks(false)
        .build()
        .await?;
    let (
        cfg,
        pool,
        ctx,
        _hub,
        _jobs,
        storage_jobs,
        reconcile_jobs,
        plugin_assets,
    ) = runtime.into_parts();

    let user_repo = SqlxUserRepository::new(pool.clone());
    let workspace_service = ctx.workspace_service();
    let ingest_queue = ctx.storage_ingest_queue();
    let session_repo = SqlxUserSessionRepository::new(pool.clone());
    let document_repo = SqlxDocumentRepository::new(pool.clone());
    let files_repo = SqlxFilesRepository::new(pool.clone());
    let plugin_installations = SqlxPluginInstallationRepository::new(pool.clone());
    let plugin_repo = SqlxPluginRepository::new(pool.clone());
    let api_tokens = SqlxApiTokenRepository::new(pool.clone());
    let shares_repo = SqlxSharesRepository::new(pool.clone());
    let git_repo =
        bootstrap::infrastructure::git::db::repositories::git_repository_sqlx::SqlxGitRepository::new(
            pool.clone(),
            cfg.encryption_key.clone(),
        );

    Ok(Deps {
        pool,
        user_repo,
        workspace_service,
        ingest_queue,
        storage_jobs,
        reconcile_jobs,
        session_repo,
        document_repo,
        files_repo,
        plugin_installations,
        plugin_repo,
        api_tokens,
        shares_repo,
        plugin_assets,
        git_repo,
    })
}
