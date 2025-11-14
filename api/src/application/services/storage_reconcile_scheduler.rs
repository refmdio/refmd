use std::sync::Arc;
use std::time::Duration;

use crate::application::ports::storage_reconcile_jobs::StorageReconcileJobs;
use crate::application::ports::user_repository::UserRepository;
use tracing::{error, info};

pub struct StorageReconcileScheduler {
    jobs: Arc<dyn StorageReconcileJobs>,
    users: Arc<dyn UserRepository>,
    interval: Duration,
}

impl StorageReconcileScheduler {
    pub fn new(
        jobs: Arc<dyn StorageReconcileJobs>,
        users: Arc<dyn UserRepository>,
        interval: Duration,
    ) -> Self {
        Self {
            jobs,
            users,
            interval,
        }
    }

    pub async fn run(self) {
        loop {
            match self.users.list_user_ids().await {
                Ok(ids) => {
                    for id in ids {
                        if let Err(err) = self.jobs.enqueue(id, "full").await {
                            error!(error = ?err, user_id = %id, "storage_reconcile_enqueue_failed");
                        } else {
                            info!(user_id = %id, "storage_reconcile_job_enqueued");
                        }
                    }
                }
                Err(err) => error!(error = ?err, "storage_reconcile_scheduler_user_list_failed"),
            }
            tokio::time::sleep(self.interval).await;
        }
    }
}
