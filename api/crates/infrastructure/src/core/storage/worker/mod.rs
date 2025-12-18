use std::sync::Arc;
use std::time::Duration;

use anyhow::Error;
use serde_json::json;
use sqlx::Error as SqlxError;
use tracing::{Instrument, error, info, info_span, warn};
use uuid::Uuid;

mod delete;
mod doc_sync;
mod folder_sync;

use crate::core::storage::suppress_git_dirty;
use application::core::ports::storage::storage_port::{StorageProjectionPort, StorageResolverPort};
use application::core::ports::storage::storage_projection_queue::{
    StorageProjectionJob, StorageProjectionJobKind, StorageProjectionQueue,
};
use application::core::services::metrics::MetricsRegistry;
use application::core::services::storage::projection_cache::RecentProjectionCache;
use application::documents::ports::doc_event_log::DocEventLog;
use application::documents::services::realtime::snapshot::MarkdownExportProvider;
use application::workspaces::services::WorkspacePermissionResolver;

pub struct StorageProjectionWorker {
    jobs: Arc<dyn StorageProjectionQueue>,
    storage: Arc<dyn StorageProjectionPort>,
    resolver: Arc<dyn StorageResolverPort>,
    markdown: Arc<dyn MarkdownExportProvider>,
    events: Arc<dyn DocEventLog>,
    recent_exports: Arc<RecentProjectionCache>,
    lock_timeout_secs: i64,
    idle_backoff: Duration,
    max_attempts: i32,
    metrics: Arc<MetricsRegistry>,
    permission_resolver: Arc<dyn WorkspacePermissionResolver>,
}

impl StorageProjectionWorker {
    pub fn new(
        jobs: Arc<dyn StorageProjectionQueue>,
        storage: Arc<dyn StorageProjectionPort>,
        resolver: Arc<dyn StorageResolverPort>,
        markdown: Arc<dyn MarkdownExportProvider>,
        events: Arc<dyn DocEventLog>,
        metrics: Arc<MetricsRegistry>,
        permission_resolver: Arc<dyn WorkspacePermissionResolver>,
        recent_exports: Arc<RecentProjectionCache>,
    ) -> Self {
        Self {
            jobs,
            storage,
            resolver,
            markdown,
            events,
            recent_exports,
            lock_timeout_secs: 30,
            idle_backoff: Duration::from_millis(500),
            max_attempts: 5,
            metrics,
            permission_resolver,
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

    pub fn with_max_attempts(mut self, attempts: i32) -> Self {
        self.max_attempts = attempts.max(1);
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

        async move {
            let delete_metadata = delete::parse_delete_job_metadata(job.reason.as_ref());
            let result = suppress_git_dirty(async {
                match job.job_type {
                    StorageProjectionJobKind::DocSync => {
                        let doc_id = job
                            .doc_id
                            .ok_or_else(|| anyhow::anyhow!("doc_id_required"))?;
                        let res = self.handle_doc_sync(doc_id).await;
                        if res.is_ok() {
                            self.emit_projection_event(doc_id, &job, "succeeded", None)
                                .await;
                        }
                        res
                    }
                    StorageProjectionJobKind::FolderSync => {
                        self.handle_folder_sync(
                            job.folder_id
                                .ok_or_else(|| anyhow::anyhow!("folder_id_required"))?,
                        )
                        .await
                    }
                    StorageProjectionJobKind::DeleteDoc => {
                        let doc_id = job
                            .doc_id
                            .ok_or_else(|| anyhow::anyhow!("doc_id_required"))?;
                        let res = self
                            .handle_delete_doc(doc_id, delete_metadata.as_ref())
                            .await;
                        if res.is_ok() {
                            self.emit_projection_event(doc_id, &job, "succeeded", None)
                                .await;
                        }
                        res
                    }
                    StorageProjectionJobKind::DeleteFolder => {
                        self.handle_delete_folder(
                            job.folder_id
                                .ok_or_else(|| anyhow::anyhow!("folder_id_required"))?,
                            delete_metadata.as_ref(),
                        )
                        .await
                    }
                }
            })
            .await;

            match result {
                Ok(()) => {
                    self.jobs.complete_job(job.id, job.locked_at).await?;
                    self.metrics.inc_storage_projection_success();
                    info!("storage_projection_job_succeeded");
                }
                Err(err) if missing_target(&err) => {
                    warn!(
                        error = ?err,
                        "storage_projection_job_missing_target_skip"
                    );
                    self.jobs.complete_job(job.id, job.locked_at).await?;
                    self.metrics.inc_storage_projection_success();
                    if let Some(doc_id) = job.doc_id {
                        self.emit_projection_event(
                            doc_id,
                            &job,
                            "skipped",
                            Some(&format!("{err:#}")),
                        )
                        .await;
                    }
                }
                Err(err) => {
                    let msg = format!("{err:#}");
                    if job.attempts >= self.max_attempts {
                        self.jobs.complete_job(job.id, job.locked_at).await?;
                        self.metrics.inc_storage_projection_failure();
                        warn!(
                            error = ?err,
                            attempts = job.attempts,
                            "storage_projection_job_gave_up"
                        );
                        if let Some(doc_id) = job.doc_id {
                            self.emit_projection_event(
                                doc_id,
                                &job,
                                "failed",
                                Some("max_attempts_exceeded"),
                            )
                            .await;
                        }
                    } else {
                        self.jobs.fail_job(job.id, job.locked_at, &msg).await?;
                        self.metrics.inc_storage_projection_retry();
                        warn!(error = ?err, "storage_projection_job_failed_once");
                        if let Some(doc_id) = job.doc_id {
                            self.emit_projection_event(doc_id, &job, "failed", Some(&msg))
                                .await;
                        }
                    }
                }
            }

            Ok(())
        }
        .instrument(span)
        .await
    }
}

impl StorageProjectionWorker {
    async fn emit_projection_event(
        &self,
        doc_id: Uuid,
        job: &StorageProjectionJob,
        status: &str,
        error: Option<&str>,
    ) {
        let Some(event_type) = projection_event_type(job.job_type) else {
            return;
        };
        let payload = json!({
            "job_id": job.id,
            "job_type": job_type_label(job.job_type),
            "status": status,
            "reason": job.reason,
            "attempts": job.attempts,
            "error": error,
        });
        if let Err(err) = self
            .events
            .append(job.workspace_id, doc_id, event_type, Some(payload))
            .await
        {
            warn!(
                error = ?err,
                doc_id = %doc_id,
                event_type,
                "storage_projection_event_emit_failed"
            );
        }
    }
}

#[cfg(test)]
mod tests;

fn missing_target(err: &Error) -> bool {
    let needle = "document not found";
    err.chain().any(|cause| {
        if let Some(sqlx_err) = cause.downcast_ref::<SqlxError>() {
            matches!(sqlx_err, SqlxError::RowNotFound)
        } else if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            io_err.kind() == std::io::ErrorKind::NotFound
        } else {
            cause.to_string().to_lowercase().contains(needle)
        }
    })
}

fn job_type_label(kind: StorageProjectionJobKind) -> &'static str {
    match kind {
        StorageProjectionJobKind::DocSync => "doc_sync",
        StorageProjectionJobKind::FolderSync => "folder_sync",
        StorageProjectionJobKind::DeleteDoc => "delete_doc",
        StorageProjectionJobKind::DeleteFolder => "delete_folder",
    }
}

fn projection_event_type(kind: StorageProjectionJobKind) -> Option<&'static str> {
    match kind {
        StorageProjectionJobKind::DocSync => Some("storage.projection.doc_sync"),
        StorageProjectionJobKind::DeleteDoc => Some("storage.projection.doc_delete"),
        _ => None,
    }
}
