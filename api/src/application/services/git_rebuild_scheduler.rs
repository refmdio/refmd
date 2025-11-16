use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info};
use uuid::Uuid;

use crate::application::ports::git_rebuild_job_queue::GitRebuildJobQueue;
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::user_repository::UserRepository;

pub struct GitRebuildScheduler {
    jobs: Arc<dyn GitRebuildJobQueue>,
    users: Arc<dyn UserRepository>,
    workspace: Arc<dyn GitWorkspacePort>,
    interval: Duration,
}

impl GitRebuildScheduler {
    pub fn new(
        jobs: Arc<dyn GitRebuildJobQueue>,
        users: Arc<dyn UserRepository>,
        workspace: Arc<dyn GitWorkspacePort>,
        interval: Duration,
    ) -> Self {
        Self {
            jobs,
            users,
            workspace,
            interval,
        }
    }

    pub async fn run(self) {
        loop {
            match self.users.list_user_ids().await {
                Ok(ids) => {
                    for user_id in ids {
                        if let Err(err) = self.enqueue_job_if_ready(user_id).await {
                            error!(error = ?err, user_id = %user_id, "git_rebuild_enqueue_failed");
                        }
                    }
                }
                Err(err) => error!(error = ?err, "git_rebuild_scheduler_user_list_failed"),
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    async fn enqueue_job_if_ready(&self, user_id: Uuid) -> anyhow::Result<()> {
        let status = self.workspace.status(user_id).await?;
        if !status.repository_initialized {
            debug!(user_id = %user_id, "git_rebuild_skip_uninitialized");
            return Ok(());
        }
        self.enqueue_job(user_id).await
    }

    async fn enqueue_job(&self, user_id: Uuid) -> anyhow::Result<()> {
        self.jobs.enqueue(user_id).await?;
        info!(user_id = %user_id, "git_rebuild_job_enqueued");
        Ok(())
    }
}
