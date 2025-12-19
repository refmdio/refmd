use std::collections::HashSet;
use std::sync::Arc;

use serde_json::json;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::core::ports::storage::storage_ingest_queue::{StorageIngestKind, StorageIngestQueue};
use crate::core::ports::storage::storage_projection_queue::{
    StorageProjectionJobKind, StorageProjectionQueue,
};
use crate::core::ports::storage::storage_reconcile_backend::StorageReconcileBackend;
use crate::core::ports::storage::storage_reconcile_jobs::{
    StorageReconcileJob, StorageReconcileJobs,
};
use crate::core::services::worker::WorkerTick;
use crate::documents::ports::document_path_repository::DocumentPathRepository;
use crate::documents::ports::files::files_repository::FilesRepository;
use domain::access::permissions::PermissionSet;
use domain::storage::ingest_backend::StorageIngestBackend;

mod paths;
use paths::{
    is_attachment_repo_path, is_reserved_repo_path, normalize_repo_path, reserved_storage_paths,
};

pub struct StorageReconcileService {
    jobs: Arc<dyn StorageReconcileJobs>,
    documents: Arc<dyn DocumentPathRepository>,
    files: Arc<dyn FilesRepository>,
    ingest_queue: Arc<dyn StorageIngestQueue>,
    storage_jobs: Arc<dyn StorageProjectionQueue>,
    backend: Arc<dyn StorageReconcileBackend>,
    ingest_known_paths: bool,
}

impl StorageReconcileService {
    pub fn new(
        jobs: Arc<dyn StorageReconcileJobs>,
        documents: Arc<dyn DocumentPathRepository>,
        files: Arc<dyn FilesRepository>,
        ingest_queue: Arc<dyn StorageIngestQueue>,
        storage_jobs: Arc<dyn StorageProjectionQueue>,
        backend: Arc<dyn StorageReconcileBackend>,
        ingest_known_paths: bool,
    ) -> Self {
        Self {
            jobs,
            documents,
            files,
            ingest_queue,
            storage_jobs,
            backend,
            ingest_known_paths,
        }
    }

    async fn enumerate_known_paths(&self, workspace_id: Uuid) -> anyhow::Result<HashSet<String>> {
        let mut paths = HashSet::new();
        for path in self.documents.list_paths_for_user(workspace_id).await? {
            if let Some(normalized) = normalize_repo_path(&path) {
                paths.insert(normalized);
            }
        }
        for attachment_path in self
            .files
            .list_storage_paths_for_workspace(workspace_id)
            .await?
        {
            if let Some(normalized) = normalize_repo_path(&attachment_path) {
                paths.insert(normalized);
            }
        }
        for reserved in reserved_storage_paths(workspace_id) {
            paths.insert(reserved);
        }
        Ok(paths)
    }

    async fn enumerate_storage_paths(&self, workspace_id: Uuid) -> anyhow::Result<Vec<String>> {
        self.backend
            .list_paths(workspace_id)
            .await
            .map_err(Into::into)
    }

    fn repo_relative_path(workspace_id: Uuid, storage_path: &str) -> Option<String> {
        let trimmed = storage_path.trim_start_matches('/');
        let prefix = workspace_id.to_string();
        let rest = trimmed.strip_prefix(&prefix)?;
        let repo = rest.trim_start_matches('/');
        if repo.is_empty() {
            None
        } else {
            Some(repo.to_string())
        }
    }

    async fn enqueue_delete(&self, workspace_id: Uuid, storage_path: &str) -> anyhow::Result<()> {
        let Some(repo_path) = Self::repo_relative_path(workspace_id, storage_path) else {
            warn!(
                workspace_id = %workspace_id,
                storage_path,
                "storage_reconcile_repo_path_unparseable"
            );
            return Ok(());
        };
        let permissions = PermissionSet::all().to_vec();
        self.ingest_queue
            .enqueue_event(
                workspace_id,
                workspace_id,
                None,
                &repo_path,
                StorageIngestBackend::Reconcile,
                StorageIngestKind::Delete,
                None,
                Some(json!({
                    "source": "reconcile",
                    "storage_path": storage_path,
                })),
                &permissions,
            )
            .await
            .map_err(Into::into)
    }

    async fn enqueue_upsert(&self, workspace_id: Uuid, storage_path: &str) -> anyhow::Result<()> {
        let Some(repo_path) = Self::repo_relative_path(workspace_id, storage_path) else {
            warn!(
                workspace_id = %workspace_id,
                storage_path,
                "storage_reconcile_repo_path_unparseable"
            );
            return Ok(());
        };

        if is_reserved_repo_path(&repo_path) {
            return Ok(());
        }

        let permissions = PermissionSet::all().to_vec();
        self.ingest_queue
            .enqueue_event(
                workspace_id,
                workspace_id,
                None,
                &repo_path,
                StorageIngestBackend::Reconcile,
                StorageIngestKind::Upsert,
                None,
                Some(json!({
                    "source": "reconcile",
                    "storage_path": storage_path,
                })),
                &permissions,
            )
            .await
            .map_err(Into::into)
    }

    async fn process_job(&self, job: &StorageReconcileJob) -> anyhow::Result<()> {
        let known = self.enumerate_known_paths(job.workspace_id).await?;
        let storage_paths = self.enumerate_storage_paths(job.workspace_id).await?;
        let mut seen: HashSet<String> = HashSet::new();
        for raw_path in storage_paths {
            let Some(path) = normalize_repo_path(&raw_path) else {
                continue;
            };
            if !known.contains(&path) {
                info!(
                    workspace_id = %job.workspace_id,
                    repo_path = path,
                    "storage_reconcile_orphan_detected"
                );
                self.enqueue_delete(job.workspace_id, &path).await?;
                continue;
            }
            seen.insert(path.clone());

            if self.ingest_known_paths {
                self.enqueue_upsert(job.workspace_id, &path).await?;
            }
        }

        for missing in known.difference(&seen) {
            self.handle_missing_path(job.workspace_id, missing).await?;
        }
        Ok(())
    }

    async fn handle_missing_path(
        &self,
        workspace_id: Uuid,
        storage_path: &str,
    ) -> anyhow::Result<()> {
        let Some(repo_path) = Self::repo_relative_path(workspace_id, storage_path) else {
            warn!(
                workspace_id = %workspace_id,
                storage_path,
                "storage_reconcile_missing_path_invalid"
            );
            return Ok(());
        };
        if is_reserved_repo_path(&repo_path) {
            return Ok(());
        }
        if is_attachment_repo_path(&repo_path) {
            info!(
                workspace_id = %workspace_id,
                repo_path = repo_path,
                "storage_reconcile_missing_attachment_cleanup"
            );
            self.enqueue_delete(workspace_id, storage_path).await?;
            return Ok(());
        }

        match self
            .documents
            .get_by_owner_and_path(workspace_id, storage_path)
            .await?
        {
            Some(doc) => {
                info!(
                    workspace_id = %workspace_id,
                    doc_id = %doc.id(),
                    repo_path = repo_path,
                    "storage_reconcile_missing_doc_enqueued"
                );
                self.storage_jobs
                    .enqueue_doc_job(
                        doc.workspace_id(),
                        doc.id(),
                        StorageProjectionJobKind::DocSync,
                        Some("storage_reconcile_missing_doc"),
                    )
                    .await?;
            }
            None => {
                warn!(
                    workspace_id = %workspace_id,
                    repo_path = repo_path,
                    "storage_reconcile_missing_doc_unknown"
                );
            }
        }
        Ok(())
    }

    pub async fn tick(&self) -> anyhow::Result<WorkerTick> {
        match self.jobs.fetch_next(30).await {
            Ok(Some(job)) => {
                if let Err(err) = self.process_job(&job).await {
                    error!(error = ?err, job_id = job.id, "storage_reconcile_job_failed");
                    let _ = self.jobs.fail(job.id, &format!("{err:#}")).await;
                } else {
                    let _ = self.jobs.complete(job.id).await;
                }
                Ok(WorkerTick::Processed)
            }
            Ok(None) => Ok(WorkerTick::Idle),
            Err(err) => Err(err.into()),
        }
    }
}
