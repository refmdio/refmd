use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, info_span, warn};
use uuid::Uuid;

use crate::application::ports::storage_port::StoragePort;
use crate::application::ports::storage_projection_queue::{
    StorageProjectionJob, StorageProjectionJobKind, StorageProjectionQueue,
};

pub struct StorageProjectionWorker {
    jobs: Arc<dyn StorageProjectionQueue>,
    storage: Arc<dyn StoragePort>,
    lock_timeout_secs: i64,
    idle_backoff: Duration,
}

impl StorageProjectionWorker {
    pub fn new(jobs: Arc<dyn StorageProjectionQueue>, storage: Arc<dyn StoragePort>) -> Self {
        Self {
            jobs,
            storage,
            lock_timeout_secs: 30,
            idle_backoff: Duration::from_millis(500),
        }
    }

    pub fn with_lock_timeout(mut self, secs: i64) -> Self {
        self.lock_timeout_secs = secs;
        self
    }

    pub fn with_idle_backoff(mut self, backoff: Duration) -> Self {
        self.idle_backoff = backoff;
        self
    }

    pub async fn run(self: Arc<Self>) {
        loop {
            match self.jobs.fetch_next_job(self.lock_timeout_secs).await {
                Ok(Some(job)) => {
                    if let Err(err) = self.process_job(job).await {
                        error!(error = ?err, "storage_projection_job_failed");
                    }
                    continue;
                }
                Ok(None) => {
                    tokio::time::sleep(self.idle_backoff).await;
                }
                Err(err) => {
                    error!(error = ?err, "storage_projection_job_fetch_failed");
                    tokio::time::sleep(self.idle_backoff).await;
                }
            }
        }
    }

    async fn process_job(self: &Arc<Self>, job: StorageProjectionJob) -> anyhow::Result<()> {
        let span = info_span!(
            "storage_projection_job",
            job_id = job.id,
            job_type = ?job.job_type,
            doc_id = job.doc_id.map(|id| id.to_string()),
            folder_id = job.folder_id.map(|id| id.to_string())
        );
        let _entered = span.enter();

        let result = match job.job_type {
            StorageProjectionJobKind::DocSync => {
                self.handle_doc_sync(
                    job.doc_id
                        .ok_or_else(|| anyhow::anyhow!("doc_id_required"))?,
                )
                .await
            }
            StorageProjectionJobKind::FolderSync => {
                self.handle_folder_sync(
                    job.folder_id
                        .ok_or_else(|| anyhow::anyhow!("folder_id_required"))?,
                )
                .await
            }
            StorageProjectionJobKind::DeleteDoc => {
                self.handle_delete_doc(
                    job.doc_id
                        .ok_or_else(|| anyhow::anyhow!("doc_id_required"))?,
                )
                .await
            }
            StorageProjectionJobKind::DeleteFolder => {
                self.handle_delete_folder(
                    job.folder_id
                        .ok_or_else(|| anyhow::anyhow!("folder_id_required"))?,
                )
                .await
            }
        };

        match result {
            Ok(()) => {
                self.jobs.complete_job(job.id).await?;
                info!("storage_projection_job_succeeded");
            }
            Err(err) => {
                let msg = format!("{err:#}");
                self.jobs.fail_job(job.id, &msg).await?;
                warn!(error = ?err, "storage_projection_job_failed_once");
            }
        }

        Ok(())
    }

    async fn handle_doc_sync(&self, doc_id: Uuid) -> anyhow::Result<()> {
        self.storage.sync_doc_paths(doc_id).await
    }

    async fn handle_folder_sync(&self, folder_id: Uuid) -> anyhow::Result<()> {
        self.storage.move_folder_subtree(folder_id).await?;
        Ok(())
    }

    async fn handle_delete_doc(&self, doc_id: Uuid) -> anyhow::Result<()> {
        self.storage.delete_doc_physical(doc_id).await
    }

    async fn handle_delete_folder(&self, folder_id: Uuid) -> anyhow::Result<()> {
        self.storage.delete_folder_physical(folder_id).await?;
        Ok(())
    }
}
