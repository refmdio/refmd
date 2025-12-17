use std::sync::Arc;

use anyhow::Context;
use tracing::info;


use application::git::ports::git_rebuild_job_queue::GitRebuildJobQueue;
use application::core::ports::storage::storage_port::StorageResolverPort;
use application::git::services::GitService;
use application::git::services::rebuild::GitRebuildService;
use application::git::services::rebuild_scheduler::GitRebuildScheduler;
use application::core::services::metrics::MetricsRegistry;
use application::documents::services::realtime::snapshot::SnapshotService;
use application::workspaces::services::WorkspacePermissionResolver;
use crate::config::{Config, StorageBackend};
use infrastructure::core::db::PgPool;
use infrastructure::git::PgGitRebuildJobQueue;
use infrastructure::git::storage::{GitStorageDriverConfig, build_git_storage};
use infrastructure::git::workspace::GitWorkspaceService;

pub struct GitRebuildStack {
    pub service: Arc<GitRebuildService>,
    pub scheduler: GitRebuildScheduler,
}

pub struct GitStack {
    pub workspace: Arc<GitWorkspaceService>,
    pub service: Arc<GitService>,
    pub repo: Arc<dyn application::git::ports::git_repository::GitRepository>,
    pub rebuild: Option<GitRebuildStack>,
    pub rebuild_jobs: Arc<dyn GitRebuildJobQueue>,
}

pub fn git_storage_driver_config(cfg: &Config) -> anyhow::Result<GitStorageDriverConfig> {
    let uploads_root = std::path::PathBuf::from(&cfg.storage_root);
    let config = match cfg.storage_backend {
        StorageBackend::Filesystem => GitStorageDriverConfig::Filesystem {
            root: uploads_root.clone(),
        },
        StorageBackend::S3 => {
            let s3_settings = infrastructure::git::storage::S3GitStorageConfig {
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

#[allow(clippy::too_many_arguments)]
pub async fn build_git_stack(
    cfg: &Config,
    pool: &PgPool,
    storage_resolver: Arc<dyn StorageResolverPort>,
    snapshot_service: Arc<SnapshotService>,
    realtime_engine: Arc<dyn application::documents::ports::realtime::realtime_port::RealtimeEngine>,
    document_repo: Arc<dyn application::documents::ports::document_repository::DocumentRepository>,
    files_repo: Arc<dyn application::documents::ports::files::files_repository::FilesRepository>,
    workspace_permissions: Arc<dyn WorkspacePermissionResolver>,
    metrics: Arc<MetricsRegistry>,
) -> anyhow::Result<GitStack> {
    let git_rebuild_jobs: Arc<dyn GitRebuildJobQueue> =
        Arc::new(PgGitRebuildJobQueue::new(pool.clone()));

    let git_repo = Arc::new(
        infrastructure::git::db::repositories::git_repository_sqlx::SqlxGitRepository::new(
            pool.clone(),
            cfg.encryption_key.clone(),
        ),
    );
    let git_pull_sessions = Arc::new(
        infrastructure::git::db::repositories::git_pull_session_repository_sqlx::GitPullSessionRepositorySqlx::new(
            pool.clone(),
        ),
    );
    let git_storage_cfg = git_storage_driver_config(cfg)?;
    let git_storage = build_git_storage(git_storage_cfg).await?;
    let gitignore_port = Arc::new(infrastructure::core::storage::gitignore::FsGitignorePort);
    let git_workspace = Arc::new(GitWorkspaceService::new(
        pool.clone(),
        git_storage.clone(),
        storage_resolver.clone(),
        snapshot_service.clone(),
        realtime_engine.clone(),
        document_repo.clone(),
    )?);
    let git_service = Arc::new(GitService::new(
        git_repo.clone(),
        storage_resolver.clone(),
        files_repo.clone(),
        document_repo.clone(),
        gitignore_port.clone(),
        git_workspace.clone(),
        git_pull_sessions.clone(),
    ));

    let rebuild = if cfg.git_rebuild_enabled {
        let rebuild_service = Arc::new(GitRebuildService::new(
            git_rebuild_jobs.clone(),
            git_workspace.clone(),
            git_repo.clone(),
            metrics.clone(),
            workspace_permissions,
        ));
        let rebuild_scheduler = GitRebuildScheduler::new(
            git_rebuild_jobs.clone(),
            git_repo.clone(),
            git_workspace.clone(),
            std::time::Duration::from_secs(cfg.git_rebuild_interval_secs),
        );
        info!("git_rebuild_scheduler_enabled");
        Some(GitRebuildStack {
            service: rebuild_service,
            scheduler: rebuild_scheduler,
        })
    } else {
        info!("git_rebuild_scheduler_disabled");
        None
    };

    Ok(GitStack {
        workspace: git_workspace,
        service: git_service,
        repo: git_repo,
        rebuild,
        rebuild_jobs: git_rebuild_jobs,
    })
}
