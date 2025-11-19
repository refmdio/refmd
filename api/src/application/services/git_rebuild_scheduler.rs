use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info};
use uuid::Uuid;

use crate::application::ports::git_rebuild_job_queue::GitRebuildJobQueue;
use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::domain::workspaces::permissions::{
    PERM_GIT_CONFIGURE, PERM_GIT_INIT, PERM_GIT_SYNC, PermissionSet,
};

const GIT_BACKGROUND_PERMISSIONS: &[&str] = &[PERM_GIT_SYNC, PERM_GIT_CONFIGURE, PERM_GIT_INIT];

pub struct GitRebuildScheduler {
    jobs: Arc<dyn GitRebuildJobQueue>,
    git_repo: Arc<dyn GitRepository>,
    workspace: Arc<dyn GitWorkspacePort>,
    interval: Duration,
}

impl GitRebuildScheduler {
    pub fn new(
        jobs: Arc<dyn GitRebuildJobQueue>,
        git_repo: Arc<dyn GitRepository>,
        workspace: Arc<dyn GitWorkspacePort>,
        interval: Duration,
    ) -> Self {
        Self {
            jobs,
            git_repo,
            workspace,
            interval,
        }
    }

    pub async fn run(self) {
        loop {
            match self.git_repo.list_auto_sync_workspaces().await {
                Ok(ids) => {
                    for workspace_id in ids {
                        if let Err(err) = self.enqueue_job_if_ready(workspace_id).await {
                            error!(
                                error = ?err,
                                workspace_id = %workspace_id,
                                "git_rebuild_enqueue_failed"
                            );
                        }
                    }
                }
                Err(err) => error!(error = ?err, "git_rebuild_scheduler_workspace_list_failed"),
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    async fn enqueue_job_if_ready(&self, workspace_id: Uuid) -> anyhow::Result<()> {
        let status = self.workspace.status(workspace_id).await?;
        if !status.repository_initialized {
            debug!(workspace_id = %workspace_id, "git_rebuild_skip_uninitialized");
            return Ok(());
        }
        self.enqueue_job(workspace_id).await
    }

    async fn enqueue_job(&self, workspace_id: Uuid) -> anyhow::Result<()> {
        let permissions = PermissionSet::from_slice(GIT_BACKGROUND_PERMISSIONS).to_vec();
        self.jobs.enqueue(workspace_id, None, &permissions).await?;
        info!(workspace_id = %workspace_id, "git_rebuild_job_enqueued");
        Ok(())
    }
}
