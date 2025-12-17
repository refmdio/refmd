use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{error, info};

use application::git::ports::git_rebuild_job_queue::GitRebuildJobQueue;
use application::plugins::ports::plugin_asset_store::PluginAssetStore;
use application::core::ports::storage::storage_projection_queue::StorageProjectionQueue;
use application::core::ports::storage::storage_reconcile_jobs::StorageReconcileJobs;
use infrastructure::core::db::PgPool;
use presentation::context::AppContext;

use crate::jobs::{self, Jobs};
use crate::{app::AppRuntime, http};

impl AppRuntime {
    /// Consume the runtime and return owned parts for reuse.
    pub fn into_parts(
        self,
    ) -> (
        crate::config::Config,
        PgPool,
        AppContext,
        Option<infrastructure::documents::realtime::Hub>,
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

        let server =
            axum::serve(listener, app).with_graceful_shutdown(jobs::wait_for_shutdown_signal());
        match server.await {
            Ok(()) => {}
            Err(e) => error!(?e, "API server failed"),
        }

        // Abort background jobs on exit.
        jobs.shutdown().await;
        Ok(())
    }
}
