use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Error;
use serde_json::json;
use sqlx::Error as SqlxError;
use tracing::{Instrument, error, info, info_span, warn};
use uuid::Uuid;

use application::documents::ports::doc_event_log::DocEventLog;
use application::core::ports::storage::storage_port::{StorageProjectionPort, StorageResolverPort};
use application::core::ports::storage::storage_projection_queue::{
    StorageDeleteJobMetadata, StorageJobReason, StorageProjectionJob, StorageProjectionJobKind,
    StorageProjectionQueue,
};
use application::core::services::metrics::MetricsRegistry;
use application::documents::services::realtime::snapshot::MarkdownExportProvider;
use application::core::services::storage::projection_cache::RecentProjectionCache;
use application::workspaces::services::WorkspacePermissionResolver;
use application::workspaces::services::permission_snapshot::permission_set_from_snapshot;
use domain::documents::doc_type::DocumentType;
use domain::workspaces::permissions::{
    PERM_DOC_DELETE, PERM_FILE_DELETE, PERM_FOLDER_DELETE, PermissionSet,
};
use crate::core::storage::suppress_git_dirty;

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
            let delete_metadata = parse_delete_job_metadata(job.reason.as_ref());
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

    async fn handle_doc_sync(&self, doc_id: Uuid) -> anyhow::Result<()> {
        self.storage.sync_doc_paths(doc_id).await?;
        self.persist_markdown(doc_id).await
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
        let permissions = self.permission_set_from_metadata(metadata).await?;
        if metadata.doc_type == DocumentType::Folder {
            if !permissions.allows(PERM_FOLDER_DELETE) {
                warn!(
                    workspace_id = %metadata.workspace_id,
                    "storage_projection_folder_delete_permission_denied"
                );
            }
            return Ok(());
        }
        if !permissions.allows(PERM_DOC_DELETE) {
            warn!(
                workspace_id = %metadata.workspace_id,
                "storage_projection_doc_delete_permission_denied"
            );
            return Ok(());
        }
        let Some(repo_path) = metadata.repo_path.as_deref() else {
            return Ok(());
        };
        let doc_relative = workspace_repo_relative(metadata.workspace_id, repo_path);
        self.storage.delete_relative_path(&doc_relative).await?;
        if let Some(paths) = metadata.attachment_paths.as_ref() {
            let can_delete_attachments = permissions.allows(PERM_FILE_DELETE);
            for rel in paths {
                if !can_delete_attachments {
                    warn!(
                        workspace_id = %metadata.workspace_id,
                        attachment_path = rel.as_str(),
                        "storage_projection_attachment_delete_permission_denied"
                    );
                    break;
                }
                if let Err(err) = self.storage.delete_relative_path(rel).await {
                    warn!(
                        workspace_id = %metadata.workspace_id,
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
        let permissions = self.permission_set_from_metadata(metadata).await?;
        if !permissions.allows(PERM_FOLDER_DELETE) {
            warn!(
                workspace_id = %metadata.workspace_id,
                "storage_projection_folder_delete_permission_denied"
            );
            return Ok(());
        }
        let folder_relative = workspace_repo_relative(metadata.workspace_id, repo_path);
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
            if let Some(repo_path) = export.repo_path.as_deref() {
                self.recent_exports
                    .record(export.workspace_id, repo_path, &export.content_hash);
            }
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

fn parse_delete_job_metadata(reason: Option<&String>) -> Option<StorageDeleteJobMetadata> {
    reason.and_then(|raw| {
        serde_json::from_str::<StorageJobReason<StorageDeleteJobMetadata>>(raw)
            .ok()
            .and_then(|wrapper| wrapper.metadata)
    })
}

fn workspace_repo_relative(workspace_id: Uuid, repo_path: &str) -> String {
    let mut full = PathBuf::from(workspace_id.to_string());
    full.push(repo_path.trim_start_matches('/'));
    normalize_relative_path(full)
}

const FALLBACK_DELETE_PERMISSIONS: &[&str] =
    &[PERM_DOC_DELETE, PERM_FOLDER_DELETE, PERM_FILE_DELETE];

impl StorageProjectionWorker {
    async fn permission_set_from_metadata(
        &self,
        metadata: &StorageDeleteJobMetadata,
    ) -> anyhow::Result<PermissionSet> {
        let set = permission_set_from_snapshot(&metadata.permission_snapshot);
        if !set.is_empty() {
            return Ok(set);
        }
        if let Some(actor_id) = metadata.actor_id {
            match self
                .permission_resolver
                .load_permission_set(metadata.workspace_id, actor_id)
                .await
            {
                Ok(Some(resolved)) => {
                    info!(
                        workspace_id = %metadata.workspace_id,
                        actor_id = %actor_id,
                        "storage_projection_permissions_rehydrated"
                    );
                    return Ok(resolved);
                }
                Ok(None) => {
                    warn!(
                        workspace_id = %metadata.workspace_id,
                        actor_id = %actor_id,
                        "storage_projection_actor_missing_for_permissions"
                    );
                }
                Err(err) => {
                    warn!(
                        error = ?err,
                        workspace_id = %metadata.workspace_id,
                        actor_id = %actor_id,
                        "storage_projection_permission_resolve_failed"
                    );
                }
            }
        } else {
            warn!(
                workspace_id = %metadata.workspace_id,
                "storage_projection_permission_snapshot_missing_no_actor"
            );
        }
        Ok(PermissionSet::from_slice(FALLBACK_DELETE_PERMISSIONS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use application::core::ports::storage::storage_port::StoredAttachment;
    use application::core::services::errors::ServiceError;
    use application::documents::services::realtime::snapshot::{
        MarkdownExport, MarkdownExportProvider,
    };

    struct AllowAllPermissions;

    #[async_trait]
    impl WorkspacePermissionResolver for AllowAllPermissions {
        async fn load_permission_set(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
        ) -> Result<Option<PermissionSet>, ServiceError> {
            Ok(Some(PermissionSet::all()))
        }
    }

    struct RecordingPermissionResolver {
        called: AtomicBool,
    }

    impl RecordingPermissionResolver {
        fn new() -> Self {
            Self {
                called: AtomicBool::new(false),
            }
        }

        fn was_called(&self) -> bool {
            self.called.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl WorkspacePermissionResolver for RecordingPermissionResolver {
        async fn load_permission_set(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
        ) -> Result<Option<PermissionSet>, ServiceError> {
            self.called.store(true, Ordering::SeqCst);
            Ok(Some(PermissionSet::from_slice(&[
                PERM_DOC_DELETE,
                PERM_FOLDER_DELETE,
            ])))
        }
    }

    struct NonePermissionResolver;

    #[async_trait]
    impl WorkspacePermissionResolver for NonePermissionResolver {
        async fn load_permission_set(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
        ) -> Result<Option<PermissionSet>, ServiceError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn doc_sync_invokes_storage_and_completes_job() {
        let queue = Arc::new(MockQueue::default());
        let storage = Arc::new(RecordingStoragePort::default());
        let resolver_impl = Arc::new(MockResolver::default());
        let resolver: Arc<dyn StorageResolverPort> = resolver_impl.clone();
        let markdown: Arc<dyn MarkdownExportProvider> = Arc::new(MockMarkdownExporter::new());
        let events = Arc::new(RecordingDocEventLog::default());
        let metrics = Arc::new(MetricsRegistry::default());
        let permission_resolver: Arc<dyn WorkspacePermissionResolver> =
            Arc::new(AllowAllPermissions);
        let worker = Arc::new(StorageProjectionWorker::new(
            queue.clone(),
            storage.clone(),
            resolver.clone(),
            markdown.clone(),
            events.clone(),
            metrics.clone(),
            permission_resolver.clone(),
            Arc::new(RecentProjectionCache::new(Duration::from_secs(5))),
        ));
        let job = StorageProjectionJob {
            id: 1,
            workspace_id: Uuid::new_v4(),
            job_type: StorageProjectionJobKind::DocSync,
            doc_id: Some(Uuid::new_v4()),
            folder_id: None,
            reason: None,
            attempts: 0,
            locked_at: chrono::Utc::now(),
        };
        worker.process_job(job).await.unwrap();
        assert_eq!(queue.completed(), vec![1]);
        assert_eq!(storage.calls(), vec!["sync_doc_paths".to_string()]);
        assert_eq!(events.events().len(), 1);
        assert_eq!(events.events()[0].2, "storage.projection.doc_sync");
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
        let permission_resolver: Arc<dyn WorkspacePermissionResolver> =
            Arc::new(AllowAllPermissions);
        let worker = Arc::new(StorageProjectionWorker::new(
            queue.clone(),
            storage,
            resolver,
            markdown,
            events,
            metrics.clone(),
            permission_resolver.clone(),
            Arc::new(RecentProjectionCache::new(Duration::from_secs(5))),
        ));
        let job = StorageProjectionJob {
            id: 2,
            workspace_id: Uuid::new_v4(),
            job_type: StorageProjectionJobKind::DocSync,
            doc_id: Some(Uuid::new_v4()),
            folder_id: None,
            reason: None,
            attempts: 0,
            locked_at: chrono::Utc::now(),
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
        let permission_resolver: Arc<dyn WorkspacePermissionResolver> =
            Arc::new(AllowAllPermissions);
        let worker = Arc::new(StorageProjectionWorker::new(
            queue,
            storage.clone(),
            resolver,
            markdown,
            events,
            metrics,
            permission_resolver.clone(),
            Arc::new(RecentProjectionCache::new(Duration::from_secs(5))),
        ));
        let owner = Uuid::new_v4();
        let metadata = StorageDeleteJobMetadata {
            workspace_id: owner,
            repo_path: Some("docs/foo.md".into()),
            doc_type: DocumentType::Document,
            attachment_paths: Some(vec![
                format!("{}/docs/attachments/image.png", owner),
                format!("{}/docs/attachments/asset.bin", owner),
            ]),
            permission_snapshot: PermissionSet::all().to_vec(),
            actor_id: None,
        };
        worker.delete_doc_by_metadata(&metadata).await.unwrap();
        assert_eq!(
            storage.calls(),
            vec![
                format!("delete_relative_path:{}/docs/foo.md", owner),
                format!("delete_relative_path:{}/docs/attachments/image.png", owner),
                format!("delete_relative_path:{}/docs/attachments/asset.bin", owner)
            ]
        );
    }

    #[tokio::test]
    async fn empty_snapshot_uses_resolver_permissions_when_available() {
        let queue = Arc::new(MockQueue::default());
        let storage = Arc::new(RecordingStoragePort::default());
        let resolver_impl = Arc::new(MockResolver::default());
        let resolver: Arc<dyn StorageResolverPort> = resolver_impl.clone();
        let markdown: Arc<dyn MarkdownExportProvider> = Arc::new(MockMarkdownExporter::new());
        let events = Arc::new(RecordingDocEventLog::default());
        let metrics = Arc::new(MetricsRegistry::default());
        let resolver_stub = Arc::new(RecordingPermissionResolver::new());
        let permission_resolver: Arc<dyn WorkspacePermissionResolver> = resolver_stub.clone();
        let worker = Arc::new(StorageProjectionWorker::new(
            queue,
            storage,
            resolver,
            markdown,
            events,
            metrics,
            permission_resolver,
            Arc::new(RecentProjectionCache::new(Duration::from_secs(5))),
        ));
        let metadata = StorageDeleteJobMetadata {
            workspace_id: Uuid::new_v4(),
            repo_path: Some("docs/foo.md".into()),
            doc_type: DocumentType::Document,
            attachment_paths: None,
            permission_snapshot: Vec::new(),
            actor_id: Some(Uuid::new_v4()),
        };
        let set = worker
            .permission_set_from_metadata(&metadata)
            .await
            .unwrap();
        assert!(resolver_stub.was_called());
        assert!(set.allows(PERM_DOC_DELETE));
    }

    #[tokio::test]
    async fn empty_snapshot_without_actor_falls_back_to_minimum_permissions() {
        let queue = Arc::new(MockQueue::default());
        let storage = Arc::new(RecordingStoragePort::default());
        let resolver_impl = Arc::new(MockResolver::default());
        let resolver: Arc<dyn StorageResolverPort> = resolver_impl.clone();
        let markdown: Arc<dyn MarkdownExportProvider> = Arc::new(MockMarkdownExporter::new());
        let events = Arc::new(RecordingDocEventLog::default());
        let metrics = Arc::new(MetricsRegistry::default());
        let permission_resolver: Arc<dyn WorkspacePermissionResolver> =
            Arc::new(NonePermissionResolver);
        let worker = Arc::new(StorageProjectionWorker::new(
            queue,
            storage,
            resolver,
            markdown,
            events,
            metrics,
            permission_resolver,
            Arc::new(RecentProjectionCache::new(Duration::from_secs(5))),
        ));
        let metadata = StorageDeleteJobMetadata {
            workspace_id: Uuid::new_v4(),
            repo_path: Some("docs/foo.md".into()),
            doc_type: DocumentType::Document,
            attachment_paths: None,
            permission_snapshot: Vec::new(),
            actor_id: None,
        };
        let set = worker
            .permission_set_from_metadata(&metadata)
            .await
            .unwrap();
        assert!(set.allows(PERM_DOC_DELETE));
        assert!(set.allows(PERM_FOLDER_DELETE));
        assert!(set.allows(PERM_FILE_DELETE));
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
            _workspace_id: Uuid,
            _doc_id: Uuid,
            _kind: StorageProjectionJobKind,
            _reason: Option<&str>,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn enqueue_folder_job(
            &self,
            _workspace_id: Uuid,
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

        async fn complete_job(
            &self,
            job_id: i64,
            _locked_at: chrono::DateTime<chrono::Utc>,
        ) -> anyhow::Result<()> {
            self.completed.lock().unwrap().push(job_id);
            Ok(())
        }

        async fn fail_job(
            &self,
            job_id: i64,
            _locked_at: chrono::DateTime<chrono::Utc>,
            error: &str,
        ) -> anyhow::Result<()> {
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
                workspace_id: Uuid::new_v4(),
                content_hash: "hash".into(),
            }))
        }
    }

    #[derive(Default)]
    struct RecordingDocEventLog {
        events: Mutex<Vec<(Uuid, Uuid, String, Option<serde_json::Value>)>>,
    }

    impl RecordingDocEventLog {
        fn events(&self) -> Vec<(Uuid, Uuid, String, Option<serde_json::Value>)> {
            self.events.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DocEventLog for RecordingDocEventLog {
        async fn append(
            &self,
            workspace_id: Uuid,
            doc_id: Uuid,
            event_type: &str,
            payload: Option<serde_json::Value>,
        ) -> anyhow::Result<()> {
            self.events.lock().unwrap().push((
                workspace_id,
                doc_id,
                event_type.to_string(),
                payload,
            ));
            Ok(())
        }
    }
}

fn normalize_relative_path(path: PathBuf) -> String {
    path.to_string_lossy().replace('\\', "/")
}

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
