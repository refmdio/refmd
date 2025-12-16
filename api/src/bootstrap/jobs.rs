use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures_util::FutureExt;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate as api;

use api::bootstrap::config::Config;
use api::bootstrap::git::GitRebuildStack;
use api::application::ports::plugin_asset_store::PluginAssetStore;
use api::infrastructure::db::PgPool;
use api::infrastructure::db::advisory_lock::AdvisoryLock;
use api::infrastructure::documents::event_poller::DocEventPoller;
use api::infrastructure::plugins::s3_store::S3BackedPluginStore;
use api::infrastructure::realtime::Hub;
use api::infrastructure::storage::{
    FsIngestWatcher, StorageConsistencyMonitor, StorageIngestWorker, StorageProjectionWorker,
};
use api::application::ports::plugin_installation_repository::PluginInstallationRepository;
use api::application::ports::user_session_repository::UserSessionRepository;
use api::application::services::storage_reconcile::StorageReconcileService;
use api::application::services::storage_reconcile_scheduler::StorageReconcileScheduler;

/// Handle to a background task.
pub struct JobHandle {
    pub name: &'static str,
    pub handle: JoinHandle<()>,
}

/// Small registry to keep track of spawned background jobs.
pub struct Jobs {
    handles: Vec<JobHandle>,
}

impl Jobs {
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    /// Spawn a background task and record its handle.
    pub fn spawn<F>(&mut self, name: &'static str, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::spawn(async move {
            if let Err(panic) = AssertUnwindSafe(fut).catch_unwind().await {
                error!(?panic, job = name, "background_job_panicked");
            }
        });
        self.handles.push(JobHandle { name, handle });
    }

    /// Expose handles for inspection or later coordination.
    pub fn handles(&self) -> &[JobHandle] {
        &self.handles
    }

    /// Abort all tracked jobs and await their termination.
    pub async fn shutdown(self) {
        for JobHandle { name, handle } in self.handles {
            handle.abort();
            match handle.await {
                Ok(()) => {}
                Err(err) if err.is_cancelled() => {
                    debug!(job = name, "background_job_cancelled");
                }
                Err(err) => {
                    error!(job = name, error = ?err, "background_job_join_failed");
                }
            }
        }
    }
}

/// Wait for Ctrl+C or SIGTERM and log which signal was received.
pub async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("create SIGTERM listener");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown_signal_received: ctrl_c");
            }
            _ = sigterm.recv() => {
                info!("shutdown_signal_received: sigterm");
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutdown_signal_received: ctrl_c");
    }
}

pub const SESSION_CLEANUP_INTERVAL_SECS: u64 = 15 * 60;
pub const SESSION_CLEANUP_BATCH_SIZE: i64 = 500;
const SNAPSHOT_LOCK_KEY: i64 = i64::from_be_bytes(*b"REFSNAP1");

pub fn spawn_storage_consistency_monitor(
    jobs: &mut Jobs,
    enabled: bool,
    spawn_background_tasks: bool,
    monitor: Arc<StorageConsistencyMonitor>,
) {
    if enabled && spawn_background_tasks {
        jobs.spawn("storage_consistency_monitor", async move {
            monitor.run().await;
        });
    }
}

pub fn spawn_fs_ingest_watcher(
    jobs: &mut Jobs,
    spawn_background_tasks: bool,
    watcher: Arc<FsIngestWatcher>,
) {
    if spawn_background_tasks {
        jobs.spawn("fs_ingest_watcher", async move {
            watcher.run().await;
        });
    }
}

pub fn spawn_doc_event_poller(
    jobs: &mut Jobs,
    spawn_background_tasks: bool,
    poller: Arc<DocEventPoller>,
) {
    if spawn_background_tasks {
        jobs.spawn("doc_event_poller", async move {
            poller.run().await;
        });
    }
}

pub fn spawn_storage_reconcile_worker(
    jobs: &mut Jobs,
    spawn_background_tasks: bool,
    svc: Arc<StorageReconcileService>,
) {
    if spawn_background_tasks {
        jobs.spawn("storage_reconcile_worker", async move {
            svc.run().await;
        });
    }
}

pub fn spawn_storage_reconcile_scheduler(
    jobs: &mut Jobs,
    spawn_background_tasks: bool,
    scheduler: StorageReconcileScheduler,
) {
    if spawn_background_tasks {
        jobs.spawn("storage_reconcile_scheduler", async move {
            scheduler.run().await;
        });
    }
}

pub fn spawn_storage_projection_worker(
    jobs: &mut Jobs,
    spawn_background_tasks: bool,
    worker: Arc<StorageProjectionWorker>,
) {
    if spawn_background_tasks {
        jobs.spawn("storage_projection_worker", async move {
            worker.run().await;
        });
    }
}

pub fn spawn_storage_ingest_worker(
    jobs: &mut Jobs,
    spawn_background_tasks: bool,
    worker: Arc<StorageIngestWorker>,
) {
    if spawn_background_tasks {
        jobs.spawn("storage_ingest_worker", async move {
            worker.run().await;
        });
    }
}

pub fn spawn_git_rebuild_jobs(
    jobs: &mut Jobs,
    spawn_background_tasks: bool,
    rebuild: Option<GitRebuildStack>,
) {
    if !spawn_background_tasks {
        return;
    }
    if let Some(rebuild) = rebuild {
        let svc = rebuild.service.clone();
        jobs.spawn("git_rebuild_worker", async move {
            svc.run().await;
        });
        jobs.spawn("git_rebuild_scheduler", async move {
            rebuild.scheduler.run().await;
        });
    }
}

pub fn spawn_plugin_prefetch(
    jobs: &mut Jobs,
    spawn_background_tasks: bool,
    installations: Arc<dyn PluginInstallationRepository>,
    assets: Arc<S3BackedPluginStore>,
) {
    if spawn_background_tasks {
        jobs.spawn("plugin_prefetch", async move {
            match installations.list_all().await {
                Ok(installs) => {
                    for inst in installs.into_iter().filter(|i| i.status == "enabled") {
                        if let Err(err) = assets
                            .load_user_manifest(&inst.workspace_id, &inst.plugin_id, &inst.version)
                            .await
                        {
                            warn!(
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
                    warn!(error = ?err, "list_all_plugin_installations_failed");
                }
            }
        });
    }
}

pub fn spawn_session_cleanup(
    jobs: &mut Jobs,
    spawn_background_tasks: bool,
    repo: Arc<dyn UserSessionRepository>,
    interval_secs: u64,
    batch_size: i64,
) {
    if !spawn_background_tasks {
        return;
    }
    jobs.spawn("session_cleanup", async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            let cutoff = Utc::now();
            let mut total_removed: u64 = 0;
            loop {
                match repo.delete_expired(cutoff, batch_size).await {
                    Ok(removed) => {
                        if removed == 0 {
                            break;
                        }
                        total_removed += removed;
                        if removed < batch_size as u64 {
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

pub fn spawn_snapshot_loop(
    jobs: &mut Jobs,
    spawn_background_tasks: bool,
    hub: Option<Hub>,
    cfg: Config,
    pool: PgPool,
) {
    if !spawn_background_tasks {
        return;
    }
    if let Some(hub_for_snap) = hub {
        jobs.spawn("snapshot_loop", async move {
            let interval = Duration::from_secs(cfg.snapshot_interval_secs);
            loop {
                match AdvisoryLock::try_acquire(&pool, SNAPSHOT_LOCK_KEY).await {
                    Ok(Some(lock)) => {
                        let snapshot_result = hub_for_snap
                            .snapshot_all(cfg.snapshot_keep_versions, cfg.updates_keep_window)
                            .await;

                        if let Err(e) = lock.release().await {
                            error!(error = ?e, "snapshot_lock_release_failed");
                        }

                        if let Err(e) = snapshot_result {
                            error!(error = ?e, "snapshot_loop_failed");
                        }
                    }
                    Ok(None) => {
                        debug!("snapshot_loop_skipped_lock_held");
                    }
                    Err(e) => {
                        error!(error = ?e, "snapshot_lock_error");
                    }
                }
                sleep(interval).await;
            }
        });
    }
}
