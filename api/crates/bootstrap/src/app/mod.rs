mod builder;
mod build_runtime;
mod runtime;

pub use builder::AppBuilder;

use std::sync::Arc;

use application::git::ports::git_rebuild_job_queue::GitRebuildJobQueue;
use application::plugins::ports::plugin_asset_store::PluginAssetStore;
use application::core::ports::storage::storage_projection_queue::StorageProjectionQueue;
use application::core::ports::storage::storage_reconcile_jobs::StorageReconcileJobs;
use infrastructure::core::db::PgPool;
use presentation::context::AppContext;

pub struct AppRuntime {
    cfg: crate::config::Config,
    pool: PgPool,
    ctx: AppContext,
    local_hub: Option<infrastructure::documents::realtime::Hub>,
    jobs: crate::jobs::Jobs,
    storage_job_queue: Arc<dyn StorageProjectionQueue>,
    storage_reconcile_jobs: Arc<dyn StorageReconcileJobs>,
    git_rebuild_jobs: Arc<dyn GitRebuildJobQueue>,
    plugin_assets: Arc<dyn PluginAssetStore>,
}

pub async fn run() -> anyhow::Result<()> {
    AppBuilder::from_env()?.build().await?.serve().await
}

/// Build the application runtime (infrastructure + services) without starting servers.
pub async fn build_runtime(
    cfg: crate::config::Config,
    spawn_background_tasks: bool,
) -> anyhow::Result<AppRuntime> {
    build_runtime::build_runtime(cfg, spawn_background_tasks).await
}
