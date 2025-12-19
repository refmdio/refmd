use std::sync::Arc;

use crate::core::ports::storage::storage_reconcile_jobs::StorageReconcileJobs;
use crate::workspaces::ports::workspace_repository::WorkspaceRepository;
use tracing::{error, info};

pub struct StorageReconcileScheduler {
    jobs: Arc<dyn StorageReconcileJobs>,
    workspaces: Arc<dyn WorkspaceRepository>,
}

impl StorageReconcileScheduler {
    pub fn new(
        jobs: Arc<dyn StorageReconcileJobs>,
        workspaces: Arc<dyn WorkspaceRepository>,
    ) -> Self {
        Self { jobs, workspaces }
    }

    pub async fn tick(&self) {
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
    }
}
