use std::sync::Arc;
use std::time::Duration;

use crate::ports::storage_reconcile_jobs::StorageReconcileJobs;
use crate::ports::workspace_repository::WorkspaceRepository;
use tracing::{error, info};

pub struct StorageReconcileScheduler {
    jobs: Arc<dyn StorageReconcileJobs>,
    workspaces: Arc<dyn WorkspaceRepository>,
    interval: Duration,
}

impl StorageReconcileScheduler {
    pub fn new(
        jobs: Arc<dyn StorageReconcileJobs>,
        workspaces: Arc<dyn WorkspaceRepository>,
        interval: Duration,
    ) -> Self {
        Self {
            jobs,
            workspaces,
            interval,
        }
    }

    pub async fn run(self) {
        loop {
            match self.workspaces.list_all_workspace_ids().await {
                Ok(ids) => {
                    for id in ids {
                        if let Err(err) = self.jobs.enqueue(id, "full").await {
                            error!(
                                error = ?err,
                                workspace_id = %id,
                                "storage_reconcile_enqueue_failed"
                            );
                        } else {
                            info!(workspace_id = %id, "storage_reconcile_job_enqueued");
                        }
                    }
                }
                Err(err) => error!(
                    error = ?err,
                    "storage_reconcile_scheduler_workspace_list_failed"
                ),
            }
            tokio::time::sleep(self.interval).await;
        }
    }
}
