use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use tracing::{error, info, warn};
use uuid::Uuid;
use walkdir::WalkDir;

use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::storage_ingest_queue::{StorageIngestKind, StorageIngestQueue};
use crate::application::ports::storage_reconcile_jobs::{
    StorageReconcileJob, StorageReconcileJobs,
};
use crate::infrastructure::storage::s3::S3StorageConfig;

const RESERVED_REPO_PATHS: &[&str] = &[".gitignore"]; // Files managed outside Document/Files repos

pub struct StorageReconcileService {
    jobs: Arc<dyn StorageReconcileJobs>,
    documents: Arc<dyn DocumentRepository>,
    files: Arc<dyn FilesRepository>,
    ingest_queue: Arc<dyn StorageIngestQueue>,
    backend: Arc<dyn StorageReconcileBackend>,
}

impl StorageReconcileService {
    pub fn new(
        jobs: Arc<dyn StorageReconcileJobs>,
        documents: Arc<dyn DocumentRepository>,
        files: Arc<dyn FilesRepository>,
        ingest_queue: Arc<dyn StorageIngestQueue>,
        backend: Arc<dyn StorageReconcileBackend>,
    ) -> Self {
        Self {
            jobs,
            documents,
            files,
            ingest_queue,
            backend,
        }
    }

    async fn enumerate_known_paths(&self, user_id: Uuid) -> anyhow::Result<HashSet<String>> {
        let mut paths = HashSet::new();
        let docs = self.documents.list_ids_for_user(user_id).await?;
        for doc_id in docs {
            if let Some(doc) = self.documents.get_by_id(doc_id).await? {
                if let Some(path) = doc.path {
                    paths.insert(path);
                }
                for attachment_path in self.files.list_storage_paths_for_document(doc.id).await? {
                    paths.insert(attachment_path);
                }
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
        self.ingest_queue
            .enqueue_event(
                user_id,
                &repo_path,
                "reconcile",
                StorageIngestKind::Delete,
                None,
                None,
            )
            .await
    }

    async fn process_job(&self, job: &StorageReconcileJob) -> anyhow::Result<()> {
        let known = self.enumerate_known_paths(job.user_id).await?;
        let storage_paths = self.enumerate_storage_paths(job.user_id).await?;
        for path in storage_paths {
            if !known.contains(&path) {
                info!(
                    user_id = %job.user_id,
                    repo_path = path,
                    "storage_reconcile_orphan_detected"
                );
                self.enqueue_delete(job.user_id, &path).await?;
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

#[async_trait::async_trait]
pub trait StorageReconcileBackend: Send + Sync {
    async fn list_paths(&self, user_id: Uuid) -> anyhow::Result<Vec<String>>;
}

pub struct FsReconcileBackend {
    root: PathBuf,
}

impl FsReconcileBackend {
    pub fn new(root: PathBuf) -> Arc<Self> {
        Arc::new(Self { root })
    }
}

#[async_trait::async_trait]
impl StorageReconcileBackend for FsReconcileBackend {
    async fn list_paths(&self, user_id: Uuid) -> anyhow::Result<Vec<String>> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let user_root = root.join(user_id.to_string());
            if !user_root.exists() {
                return Ok(Vec::new());
            }
            let mut paths = Vec::new();
            for entry in WalkDir::new(&user_root).into_iter().filter_map(Result::ok) {
                if entry.path().is_file() {
                    if let Some(rel) = entry
                        .path()
                        .strip_prefix(&root)
                        .ok()
                        .and_then(|p| p.to_str())
                    {
                        paths.push(rel.replace('\\', "/"));
                    }
                }
            }
            Ok(paths)
        })
        .await?
    }
}

pub struct S3ReconcileBackend {
    client: Client,
    bucket: String,
    root_prefix: String,
}

impl S3ReconcileBackend {
    pub async fn new(cfg: &S3StorageConfig) -> anyhow::Result<Arc<Self>> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Some(region) = &cfg.region {
            loader = loader.region(Region::new(region.clone()));
        }
        let shared = loader.load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if let (Some(access), Some(secret)) = (&cfg.access_key, &cfg.secret_key) {
            builder = builder.credentials_provider(Credentials::new(
                access.clone(),
                secret.clone(),
                None,
                None,
                "refmd-s3-static",
            ));
        }
        if let Some(endpoint) = &cfg.endpoint {
            builder = builder.endpoint_url(endpoint.clone());
        }
        if cfg.use_path_style {
            builder = builder.force_path_style(true);
        }
        let client = Client::from_conf(builder.build());
        Ok(Arc::new(Self {
            client,
            bucket: cfg.bucket.clone(),
            root_prefix: normalize_prefix(&cfg.uploads_root),
        }))
    }

    fn repo_path_from_key(&self, key: &str) -> Option<String> {
        let trimmed = if self.root_prefix.is_empty() {
            key
        } else {
            key.strip_prefix(&format!("{}/", self.root_prefix))
                .unwrap_or(key)
        };
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }
}

fn normalize_prefix(root: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for comp in root.components() {
        if let Component::Normal(os) = comp {
            let s = os.to_string_lossy();
            if !s.is_empty() && s != "." {
                parts.push(s.replace('\\', "/"));
            }
        }
    }
    parts.join("/")
}

fn reserved_storage_paths(user_id: Uuid) -> impl Iterator<Item = String> {
    RESERVED_REPO_PATHS
        .iter()
        .map(move |rel| format!("{}/{}", user_id, rel.trim_start_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_paths_are_under_user_root() {
        let user = Uuid::new_v4();
        let collected: Vec<String> = reserved_storage_paths(user).collect();
        assert_eq!(collected, vec![format!("{}/.gitignore", user)]);
    }
}

#[async_trait::async_trait]
impl StorageReconcileBackend for S3ReconcileBackend {
    async fn list_paths(&self, user_id: Uuid) -> anyhow::Result<Vec<String>> {
        let mut paths = Vec::new();
        let prefix = if self.root_prefix.is_empty() {
            user_id.to_string()
        } else {
            format!("{}/{}", self.root_prefix, user_id)
        };
        let mut token = None;
        loop {
            let resp = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix)
                .set_continuation_token(token.clone())
                .send()
                .await?;
            for obj in resp.contents() {
                if let Some(key) = obj.key() {
                    if let Some(repo_path) = self.repo_path_from_key(key) {
                        paths.push(repo_path);
                    }
                }
            }
            if let Some(next) = resp.next_continuation_token() {
                token = Some(next.to_string());
            } else {
                break;
            }
        }
        Ok(paths)
    }
}
