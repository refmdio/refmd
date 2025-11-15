use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Error;
use serde_json::json;
use tracing::{error, info, info_span, warn};
use uuid::Uuid;

use crate::application::ports::doc_event_log::DocEventLog;
use crate::application::ports::storage_port::{StorageProjectionPort, StorageResolverPort};
use crate::application::ports::storage_projection_queue::{
    StorageDeleteJobMetadata, StorageJobReason, StorageProjectionJob, StorageProjectionJobKind,
    StorageProjectionQueue,
};
use crate::application::services::metrics::MetricsRegistry;
use crate::application::services::realtime::snapshot::MarkdownExportProvider;

pub struct StorageProjectionWorker {
    jobs: Arc<dyn StorageProjectionQueue>,
    storage: Arc<dyn StorageProjectionPort>,
    resolver: Arc<dyn StorageResolverPort>,
    markdown: Arc<dyn MarkdownExportProvider>,
    events: Arc<dyn DocEventLog>,
    lock_timeout_secs: i64,
    idle_backoff: Duration,
    max_attempts: i32,
    metrics: Arc<MetricsRegistry>,
}

impl StorageProjectionWorker {
    pub fn new(
        jobs: Arc<dyn StorageProjectionQueue>,
        storage: Arc<dyn StorageProjectionPort>,
        resolver: Arc<dyn StorageResolverPort>,
        markdown: Arc<dyn MarkdownExportProvider>,
        events: Arc<dyn DocEventLog>,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        Self {
            jobs,
            storage,
            resolver,
            markdown,
            events,
            lock_timeout_secs: 30,
            idle_backoff: Duration::from_millis(500),
            max_attempts: 5,
            metrics,
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
        let _entered = span.enter();

        let delete_metadata = parse_delete_job_metadata(job.reason.as_ref());
        let result = match job.job_type {
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
        };

        match result {
            Ok(()) => {
                self.jobs.complete_job(job.id).await?;
                self.metrics.inc_storage_projection_success();
                info!("storage_projection_job_succeeded");
            }
            Err(err) if missing_target(&err) => {
                warn!(
                    error = ?err,
                    "storage_projection_job_missing_target_skip"
                );
                self.jobs.complete_job(job.id).await?;
                self.metrics.inc_storage_projection_success();
                if let Some(doc_id) = job.doc_id {
                    self.emit_projection_event(doc_id, &job, "skipped", Some(&format!("{err:#}")))
                        .await;
                }
            }
            Err(err) => {
                let msg = format!("{err:#}");
                if job.attempts >= self.max_attempts {
                    self.jobs.complete_job(job.id).await?;
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
                    self.jobs.fail_job(job.id, &msg).await?;
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

    async fn handle_doc_sync(&self, doc_id: Uuid) -> anyhow::Result<()> {
        self.persist_markdown(doc_id).await?;
        self.storage.sync_doc_paths(doc_id).await
    }

    async fn handle_folder_sync(&self, folder_id: Uuid) -> anyhow::Result<()> {
        self.storage.move_folder_subtree(folder_id).await?;
        Ok(())
    }

    async fn handle_delete_doc(
        &self,
        doc_id: Uuid,
        metadata: Option<&StorageDeleteJobMetadata>,
    ) -> anyhow::Result<()> {
        self.storage.delete_doc_physical(doc_id).await?;
        if let Some(meta) = metadata {
            self.delete_doc_by_metadata(meta).await?;
        }
        Ok(())
    }

    async fn handle_delete_folder(
        &self,
        folder_id: Uuid,
        metadata: Option<&StorageDeleteJobMetadata>,
    ) -> anyhow::Result<()> {
        self.storage.delete_folder_physical(folder_id).await?;
        if let Some(meta) = metadata {
            self.delete_folder_by_metadata(meta).await?;
        }
        Ok(())
    }

    async fn delete_doc_by_metadata(
        &self,
        metadata: &StorageDeleteJobMetadata,
    ) -> anyhow::Result<()> {
        if metadata.doc_type == "folder" {
            return Ok(());
        }
        let Some(repo_path) = metadata.repo_path.as_deref() else {
            return Ok(());
        };
        let doc_relative = owner_repo_relative(metadata.owner_id, repo_path);
        self.storage.delete_relative_path(&doc_relative).await?;
        if let Some(paths) = metadata.attachment_paths.as_ref() {
            for rel in paths {
                if let Err(err) = self.storage.delete_relative_path(rel).await {
                    warn!(
                        owner_id = %metadata.owner_id,
                        attachment_path = rel.as_str(),
                        error = ?err,
                        "storage_attachment_delete_failed"
                    );
                }
            }
        }
        Ok(())
    }

    async fn delete_folder_by_metadata(
        &self,
        metadata: &StorageDeleteJobMetadata,
    ) -> anyhow::Result<()> {
        let Some(repo_path) = metadata.repo_path.as_deref() else {
            return Ok(());
        };
        let folder_relative = owner_repo_relative(metadata.owner_id, repo_path);
        self.storage.delete_relative_path(&folder_relative).await?;
        Ok(())
    }
}

impl StorageProjectionWorker {
    async fn persist_markdown(&self, doc_id: Uuid) -> anyhow::Result<()> {
        if let Some(export) = self.markdown.export_markdown_for_doc(&doc_id).await? {
            let path = self.resolver.build_doc_file_path(doc_id).await?;
            self.resolver
                .write_bytes(path.as_path(), &export.bytes)
                .await?;
        }
        Ok(())
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
        if let Err(err) = self.events.append(doc_id, event_type, Some(payload)).await {
            warn!(
                error = ?err,
                doc_id = %doc_id,
                event_type,
                "storage_projection_event_emit_failed"
            );
        }
    }
}

fn parse_delete_job_metadata(reason: Option<&String>) -> Option<StorageDeleteJobMetadata> {
    reason.and_then(|raw| {
        serde_json::from_str::<StorageJobReason<StorageDeleteJobMetadata>>(raw)
            .ok()
            .and_then(|wrapper| wrapper.metadata)
    })
}

fn owner_repo_relative(owner_id: Uuid, repo_path: &str) -> String {
    let mut full = PathBuf::from(owner_id.to_string());
    full.push(repo_path.trim_start_matches('/'));
    normalize_relative_path(full)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use sqlx::{Postgres, Transaction};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::application::ports::storage_port::StoredAttachment;
    use crate::application::services::realtime::snapshot::{
        MarkdownExport, MarkdownExportProvider,
    };

    #[tokio::test]
    async fn doc_sync_invokes_storage_and_completes_job() {
        let queue = Arc::new(MockQueue::default());
        let storage = Arc::new(RecordingStoragePort::default());
        let resolver_impl = Arc::new(MockResolver::default());
        let resolver: Arc<dyn StorageResolverPort> = resolver_impl.clone();
        let markdown: Arc<dyn MarkdownExportProvider> = Arc::new(MockMarkdownExporter::new());
        let events = Arc::new(RecordingDocEventLog::default());
        let metrics = Arc::new(MetricsRegistry::default());
        let worker = Arc::new(StorageProjectionWorker::new(
            queue.clone(),
            storage.clone(),
            resolver.clone(),
            markdown.clone(),
            events.clone(),
            metrics.clone(),
        ));
        let job = StorageProjectionJob {
            id: 1,
            job_type: StorageProjectionJobKind::DocSync,
            doc_id: Some(Uuid::new_v4()),
            folder_id: None,
            reason: None,
            attempts: 0,
        };
        worker.process_job(job).await.unwrap();
        assert_eq!(queue.completed(), vec![1]);
        assert_eq!(
            storage.calls(),
            vec!["sync_doc_paths".to_string()]
        );
        assert_eq!(events.events().len(), 1);
        assert_eq!(events.events()[0].1, "storage.projection.doc_sync");
        assert_eq!(resolver_impl.writes().len(), 1);
        assert_eq!(metrics.snapshot().storage_projection_success, 1);
    }

    #[tokio::test]
    async fn failing_doc_sync_marks_job_failed() {
        let queue = Arc::new(MockQueue::default());
        let storage = Arc::new(RecordingStoragePort::default());
        storage.fail_next_sync();
        let resolver_impl = Arc::new(MockResolver::default());
        let resolver: Arc<dyn StorageResolverPort> = resolver_impl.clone();
        let markdown: Arc<dyn MarkdownExportProvider> = Arc::new(MockMarkdownExporter::new());
        let events = Arc::new(RecordingDocEventLog::default());
        let metrics = Arc::new(MetricsRegistry::default());
        let worker = Arc::new(StorageProjectionWorker::new(
            queue.clone(),
            storage,
            resolver,
            markdown,
            events,
            metrics.clone(),
        ));
        let job = StorageProjectionJob {
            id: 2,
            job_type: StorageProjectionJobKind::DocSync,
            doc_id: Some(Uuid::new_v4()),
            folder_id: None,
            reason: None,
            attempts: 0,
        };
        worker.process_job(job).await.unwrap();
        assert!(queue.completed().is_empty());
        assert_eq!(queue.failed().len(), 1);
        assert_eq!(queue.failed()[0].0, 2);
        assert_eq!(metrics.snapshot().storage_projection_retry, 1);
    }

    #[tokio::test]
    async fn delete_doc_metadata_removes_only_listed_attachments() {
        let queue = Arc::new(MockQueue::default());
        let storage = Arc::new(RecordingStoragePort::default());
        let resolver_impl = Arc::new(MockResolver::default());
        let resolver: Arc<dyn StorageResolverPort> = resolver_impl.clone();
        let markdown: Arc<dyn MarkdownExportProvider> = Arc::new(MockMarkdownExporter::new());
        let events = Arc::new(RecordingDocEventLog::default());
        let metrics = Arc::new(MetricsRegistry::default());
        let worker = Arc::new(StorageProjectionWorker::new(
            queue,
            storage.clone(),
            resolver,
            markdown,
            events,
            metrics,
        ));
        let owner = Uuid::new_v4();
        let metadata = StorageDeleteJobMetadata {
            owner_id: owner,
            repo_path: Some("docs/foo.md".into()),
            doc_type: "doc".into(),
            attachment_paths: Some(vec![
                format!("{}/docs/attachments/image.png", owner),
                format!("{}/docs/attachments/asset.bin", owner),
            ]),
        };
        worker.delete_doc_by_metadata(&metadata).await.unwrap();
        assert_eq!(
            storage.calls(),
            vec![
                format!("delete_relative_path:{}/docs/foo.md", owner),
                format!(
                    "delete_relative_path:{}/docs/attachments/image.png",
                    owner
                ),
                format!(
                    "delete_relative_path:{}/docs/attachments/asset.bin",
                    owner
                )
            ]
        );
    }

    #[derive(Default)]
    struct MockQueue {
        completed: Mutex<Vec<i64>>,
        failed: Mutex<Vec<(i64, String)>>,
    }

    impl MockQueue {
        fn completed(&self) -> Vec<i64> {
            self.completed.lock().unwrap().clone()
        }

        fn failed(&self) -> Vec<(i64, String)> {
            self.failed.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl StorageProjectionQueue for MockQueue {
        async fn enqueue_doc_job(
            &self,
            _doc_id: Uuid,
            _kind: StorageProjectionJobKind,
            _reason: Option<&str>,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn enqueue_doc_job_tx(
            &self,
            _tx: &mut Transaction<'_, Postgres>,
            _doc_id: Uuid,
            _kind: StorageProjectionJobKind,
            _reason: Option<&str>,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn enqueue_folder_job(
            &self,
            _folder_id: Uuid,
            _kind: StorageProjectionJobKind,
            _reason: Option<&str>,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn enqueue_folder_job_tx(
            &self,
            _tx: &mut Transaction<'_, Postgres>,
            _folder_id: Uuid,
            _kind: StorageProjectionJobKind,
            _reason: Option<&str>,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn fetch_next_job(
            &self,
            _lock_timeout_secs: i64,
        ) -> anyhow::Result<Option<StorageProjectionJob>> {
            Ok(None)
        }

        async fn complete_job(&self, job_id: i64) -> anyhow::Result<()> {
            self.completed.lock().unwrap().push(job_id);
            Ok(())
        }

        async fn fail_job(&self, job_id: i64, error: &str) -> anyhow::Result<()> {
            self.failed
                .lock()
                .unwrap()
                .push((job_id, error.to_string()));
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingStoragePort {
        calls: Mutex<Vec<String>>,
        fail_sync: AtomicBool,
    }

    impl RecordingStoragePort {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn fail_next_sync(&self) {
            self.fail_sync.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl StorageProjectionPort for RecordingStoragePort {
        async fn move_folder_subtree(&self, folder_id: Uuid) -> anyhow::Result<usize> {
            let _ = folder_id;
            self.calls
                .lock()
                .unwrap()
                .push("move_folder_subtree".to_string());
            Ok(0)
        }

        async fn delete_doc_physical(&self, doc_id: Uuid) -> anyhow::Result<()> {
            let _ = doc_id;
            self.calls
                .lock()
                .unwrap()
                .push("delete_doc_physical".to_string());
            Ok(())
        }

        async fn delete_folder_physical(&self, folder_id: Uuid) -> anyhow::Result<usize> {
            let _ = folder_id;
            self.calls
                .lock()
                .unwrap()
                .push("delete_folder_physical".to_string());
            Ok(0)
        }

        async fn sync_doc_paths(&self, _doc_id: Uuid) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push("sync_doc_paths".to_string());
            if self.fail_sync.swap(false, Ordering::SeqCst) {
                anyhow::bail!("sync_failed");
            }
            Ok(())
        }

        async fn delete_relative_path(&self, rel: &str) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("delete_relative_path:{rel}"));
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockResolver {
        writes: Mutex<Vec<(Uuid, Vec<u8>)>>,
    }

    impl MockResolver {
        fn writes(&self) -> Vec<(Uuid, Vec<u8>)> {
            self.writes.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl StorageResolverPort for MockResolver {
        async fn build_doc_dir(&self, _doc_id: Uuid) -> anyhow::Result<PathBuf> {
            Ok(PathBuf::from("mock"))
        }

        async fn build_doc_file_path(&self, doc_id: Uuid) -> anyhow::Result<PathBuf> {
            Ok(PathBuf::from(format!("mock/{doc_id}.md")))
        }

        fn relative_from_uploads(&self, _abs: &Path) -> String {
            "mock".into()
        }

        fn user_repo_dir(&self, _user_id: Uuid) -> String {
            "mock".into()
        }

        fn absolute_from_relative(&self, rel: &str) -> PathBuf {
            PathBuf::from(rel)
        }

        async fn resolve_upload_path(
            &self,
            _doc_id: Uuid,
            _rest_path: &str,
        ) -> anyhow::Result<PathBuf> {
            unimplemented!()
        }

        async fn read_bytes(&self, _abs_path: &Path) -> anyhow::Result<Vec<u8>> {
            unimplemented!()
        }

        async fn exists(&self, _abs_path: &Path) -> anyhow::Result<bool> {
            Ok(true)
        }

        async fn write_bytes(&self, abs_path: &Path, data: &[u8]) -> anyhow::Result<()> {
            let doc_id = abs_path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|raw| Uuid::parse_str(raw).ok())
                .unwrap_or_else(Uuid::nil);
            self.writes.lock().unwrap().push((doc_id, data.to_vec()));
            Ok(())
        }

        async fn store_doc_attachment(
            &self,
            _doc_id: Uuid,
            _original_filename: Option<&str>,
            _bytes: &[u8],
        ) -> anyhow::Result<StoredAttachment> {
            unimplemented!()
        }
    }

    struct MockMarkdownExporter {
        bytes: Vec<u8>,
    }

    impl MockMarkdownExporter {
        fn new() -> Self {
            Self {
                bytes: b"mock markdown".to_vec(),
            }
        }
    }

    #[async_trait]
    impl MarkdownExportProvider for MockMarkdownExporter {
        async fn export_markdown_for_doc(
            &self,
            _doc_id: &Uuid,
        ) -> anyhow::Result<Option<MarkdownExport>> {
            Ok(Some(MarkdownExport {
                bytes: self.bytes.clone(),
                repo_path: Some("docs/mock.md".into()),
                owner_id: Some(Uuid::new_v4()),
                content_hash: "hash".into(),
            }))
        }
    }

    #[derive(Default)]
    struct RecordingDocEventLog {
        events: Mutex<Vec<(Uuid, String, Option<serde_json::Value>)>>,
    }

    impl RecordingDocEventLog {
        fn events(&self) -> Vec<(Uuid, String, Option<serde_json::Value>)> {
            self.events.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DocEventLog for RecordingDocEventLog {
        async fn append(
            &self,
            doc_id: Uuid,
            event_type: &str,
            payload: Option<serde_json::Value>,
        ) -> anyhow::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push((doc_id, event_type.to_string(), payload));
            Ok(())
        }

        async fn append_tx(
            &self,
            _tx: &mut Transaction<'_, Postgres>,
            _doc_id: Uuid,
            _event_type: &str,
            _payload: Option<serde_json::Value>,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
    }
}

fn normalize_relative_path(path: PathBuf) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn missing_target(err: &Error) -> bool {
    let needle = "document not found";
    err.chain()
        .any(|cause| cause.to_string().to_lowercase().contains(needle))
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
