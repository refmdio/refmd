use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::storage_ingest_queue::{StorageIngestKind, StorageIngestQueue};
use crate::application::ports::storage_projection_queue::{
    StorageProjectionJobKind, StorageProjectionQueue,
};
use crate::application::ports::storage_reconcile_backend::StorageReconcileBackend;
use crate::application::ports::storage_reconcile_jobs::{
    StorageReconcileJob, StorageReconcileJobs,
};
use crate::application::services::workspaces::permissions::PermissionSet;

const RESERVED_REPO_PATHS: &[&str] = &[".gitignore"]; // Files managed outside Document/Files repos

pub struct StorageReconcileService {
    jobs: Arc<dyn StorageReconcileJobs>,
    documents: Arc<dyn DocumentRepository>,
    files: Arc<dyn FilesRepository>,
    ingest_queue: Arc<dyn StorageIngestQueue>,
    storage_jobs: Arc<dyn StorageProjectionQueue>,
    backend: Arc<dyn StorageReconcileBackend>,
    ingest_known_paths: bool,
}

impl StorageReconcileService {
    pub fn new(
        jobs: Arc<dyn StorageReconcileJobs>,
        documents: Arc<dyn DocumentRepository>,
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

    async fn enumerate_known_paths(&self, user_id: Uuid) -> anyhow::Result<HashSet<String>> {
        let mut paths = HashSet::new();
        for path in self.documents.list_paths_for_user(user_id).await? {
            if let Some(normalized) = normalize_repo_path(&path) {
                paths.insert(normalized);
            }
        }
        for attachment_path in self.files.list_storage_paths_for_workspace(user_id).await? {
            if let Some(normalized) = normalize_repo_path(&attachment_path) {
                paths.insert(normalized);
            }
        }
        for reserved in reserved_storage_paths(user_id) {
            paths.insert(reserved);
        }
        Ok(paths)
    }

    async fn enumerate_storage_paths(&self, user_id: Uuid) -> anyhow::Result<Vec<String>> {
        self.backend.list_paths(user_id).await
    }

    fn repo_relative_path(user_id: Uuid, storage_path: &str) -> Option<String> {
        let trimmed = storage_path.trim_start_matches('/');
        let prefix = user_id.to_string();
        let rest = trimmed.strip_prefix(&prefix)?;
        let repo = rest.trim_start_matches('/');
        if repo.is_empty() {
            None
        } else {
            Some(repo.to_string())
        }
    }

    async fn enqueue_delete(&self, user_id: Uuid, storage_path: &str) -> anyhow::Result<()> {
        let Some(repo_path) = Self::repo_relative_path(user_id, storage_path) else {
            warn!(
                user_id = %user_id,
                storage_path,
                "storage_reconcile_repo_path_unparseable"
            );
            return Ok(());
        };
        let permissions = PermissionSet::all().to_vec();
        self.ingest_queue
            .enqueue_event(
                user_id,
                user_id,
                None,
                &repo_path,
                "reconcile",
                StorageIngestKind::Delete,
                None,
                Some(json!({
                    "source": "reconcile",
                    "storage_path": storage_path,
                })),
                &permissions,
            )
            .await
    }

    async fn enqueue_upsert(&self, user_id: Uuid, storage_path: &str) -> anyhow::Result<()> {
        let Some(repo_path) = Self::repo_relative_path(user_id, storage_path) else {
            warn!(
                user_id = %user_id,
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
                user_id,
                user_id,
                None,
                &repo_path,
                "reconcile",
                StorageIngestKind::Upsert,
                None,
                Some(json!({
                    "source": "reconcile",
                    "storage_path": storage_path,
                })),
                &permissions,
            )
            .await
    }

    async fn process_job(&self, job: &StorageReconcileJob) -> anyhow::Result<()> {
        let known = self.enumerate_known_paths(job.user_id).await?;
        let storage_paths = self.enumerate_storage_paths(job.user_id).await?;
        let mut seen: HashSet<String> = HashSet::new();
        for raw_path in storage_paths {
            let Some(path) = normalize_repo_path(&raw_path) else {
                continue;
            };
            if !known.contains(&path) {
                info!(
                    user_id = %job.user_id,
                    repo_path = path,
                    "storage_reconcile_orphan_detected"
                );
                self.enqueue_delete(job.user_id, &path).await?;
                continue;
            }
            seen.insert(path.clone());

            if self.ingest_known_paths {
                self.enqueue_upsert(job.user_id, &path).await?;
            }
        }

        for missing in known.difference(&seen) {
            self.handle_missing_path(job.user_id, missing).await?;
        }
        Ok(())
    }

    async fn handle_missing_path(&self, user_id: Uuid, storage_path: &str) -> anyhow::Result<()> {
        let Some(repo_path) = Self::repo_relative_path(user_id, storage_path) else {
            warn!(
                user_id = %user_id,
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
                user_id = %user_id,
                repo_path = repo_path,
                "storage_reconcile_missing_attachment_cleanup"
            );
            self.enqueue_delete(user_id, storage_path).await?;
            return Ok(());
        }

        match self
            .documents
            .get_by_owner_and_path(user_id, storage_path)
            .await?
        {
            Some(doc) => {
                info!(
                    user_id = %user_id,
                    doc_id = %doc.id,
                    repo_path = repo_path,
                    "storage_reconcile_missing_doc_enqueued"
                );
                self.storage_jobs
                    .enqueue_doc_job(
                        doc.workspace_id,
                        doc.id,
                        StorageProjectionJobKind::DocSync,
                        Some("storage_reconcile_missing_doc"),
                    )
                    .await?;
            }
            None => {
                warn!(
                    user_id = %user_id,
                    repo_path = repo_path,
                    "storage_reconcile_missing_doc_unknown"
                );
            }
        }
        Ok(())
    }

    pub async fn run(self: Arc<Self>) {
        loop {
            match self.jobs.fetch_next(30).await {
                Ok(Some(job)) => {
                    if let Err(err) = self.process_job(&job).await {
                        error!(error = ?err, job_id = job.id, "storage_reconcile_job_failed");
                        let _ = self.jobs.fail(job.id, &format!("{err:#}")).await;
                    } else {
                        let _ = self.jobs.complete(job.id).await;
                    }
                }
                Ok(None) => tokio::time::sleep(Duration::from_secs(2)).await,
                Err(err) => {
                    error!(error = ?err, "storage_reconcile_fetch_failed");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
}

fn reserved_storage_paths(user_id: Uuid) -> impl Iterator<Item = String> {
    RESERVED_REPO_PATHS
        .iter()
        .map(move |rel| format!("{}/{}", user_id, rel.trim_start_matches('/')))
}

fn is_reserved_repo_path(repo_path: &str) -> bool {
    let trimmed = repo_path.trim_start_matches('/');
    RESERVED_REPO_PATHS
        .iter()
        .any(|reserved| trimmed == reserved.trim_start_matches('/'))
}

fn is_attachment_repo_path(repo_path: &str) -> bool {
    repo_path.contains("/attachments/")
}

fn normalize_repo_path(raw: &str) -> Option<String> {
    let replaced = raw.replace('\\', "/");
    let trimmed = replaced.trim_start_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{is_reserved_repo_path, normalize_repo_path, reserved_storage_paths};
    use uuid::Uuid;

    #[test]
    fn reserved_paths_are_under_user_root() {
        let user = Uuid::new_v4();
        let collected: Vec<String> = reserved_storage_paths(user).collect();
        assert_eq!(collected, vec![format!("{}/.gitignore", user)]);
    }

    #[test]
    fn normalize_handles_windows_paths() {
        let user = Uuid::new_v4();
        let path = format!(r"{}\notes\foo.md", user);
        assert_eq!(
            normalize_repo_path(&path),
            Some(format!("{}/notes/foo.md", user))
        );
    }

    #[test]
    fn normalize_filters_empty() {
        assert_eq!(normalize_repo_path(""), None);
        assert_eq!(normalize_repo_path("/"), None);
    }

    #[test]
    fn detects_reserved_repo_path() {
        assert!(is_reserved_repo_path(".gitignore"));
        assert!(is_reserved_repo_path("/.gitignore"));
        assert!(!is_reserved_repo_path("docs/foo.md"));
    }
}
