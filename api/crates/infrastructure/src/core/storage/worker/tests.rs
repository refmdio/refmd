use super::*;

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use application::core::ports::storage::storage_projection_queue::StorageDeleteJobMetadata;
use domain::access::permissions::{
    PERM_DOC_DELETE, PERM_FILE_DELETE, PERM_FOLDER_DELETE, PermissionSet,
};
use domain::documents::doc_type::DocumentType;

use application::core::ports::errors::PortResult;
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
    let permission_resolver: Arc<dyn WorkspacePermissionResolver> = Arc::new(AllowAllPermissions);
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
    let permission_resolver: Arc<dyn WorkspacePermissionResolver> = Arc::new(AllowAllPermissions);
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
    let permission_resolver: Arc<dyn WorkspacePermissionResolver> = Arc::new(AllowAllPermissions);
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
    ) -> PortResult<()> {
        unimplemented!()
    }

    async fn enqueue_folder_job(
        &self,
        _workspace_id: Uuid,
        _folder_id: Uuid,
        _kind: StorageProjectionJobKind,
        _reason: Option<&str>,
    ) -> PortResult<()> {
        unimplemented!()
    }

    async fn fetch_next_job(
        &self,
        _lock_timeout_secs: i64,
    ) -> PortResult<Option<StorageProjectionJob>> {
        Ok(None)
    }

    async fn complete_job(
        &self,
        job_id: i64,
        _locked_at: chrono::DateTime<chrono::Utc>,
    ) -> PortResult<()> {
        self.completed.lock().unwrap().push(job_id);
        Ok(())
    }

    async fn fail_job(
        &self,
        job_id: i64,
        _locked_at: chrono::DateTime<chrono::Utc>,
        error: &str,
    ) -> PortResult<()> {
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
    async fn move_folder_subtree(&self, folder_id: Uuid) -> PortResult<usize> {
        let _ = folder_id;
        self.calls
            .lock()
            .unwrap()
            .push("move_folder_subtree".to_string());
        Ok(0)
    }

    async fn delete_doc_physical(&self, doc_id: Uuid) -> PortResult<()> {
        let _ = doc_id;
        self.calls
            .lock()
            .unwrap()
            .push("delete_doc_physical".to_string());
        Ok(())
    }

    async fn delete_folder_physical(&self, folder_id: Uuid) -> PortResult<usize> {
        let _ = folder_id;
        self.calls
            .lock()
            .unwrap()
            .push("delete_folder_physical".to_string());
        Ok(0)
    }

    async fn sync_doc_paths(&self, _doc_id: Uuid) -> PortResult<()> {
        self.calls
            .lock()
            .unwrap()
            .push("sync_doc_paths".to_string());
        if self.fail_sync.swap(false, Ordering::SeqCst) {
            return Err(anyhow::anyhow!("sync_failed").into());
        }
        Ok(())
    }

    async fn delete_relative_path(&self, rel: &str) -> PortResult<()> {
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
    async fn build_doc_dir(&self, _doc_id: Uuid) -> PortResult<PathBuf> {
        Ok(PathBuf::from("mock"))
    }

    async fn build_doc_file_path(&self, doc_id: Uuid) -> PortResult<PathBuf> {
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

    async fn resolve_upload_path(&self, _doc_id: Uuid, _rest_path: &str) -> PortResult<PathBuf> {
        unimplemented!()
    }

    async fn read_bytes(&self, _abs_path: &Path) -> PortResult<Vec<u8>> {
        unimplemented!()
    }

    async fn exists(&self, _abs_path: &Path) -> PortResult<bool> {
        Ok(true)
    }

    async fn write_bytes(&self, abs_path: &Path, data: &[u8]) -> PortResult<()> {
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
    ) -> PortResult<StoredAttachment> {
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
    events: Mutex<Vec<RecordedDocEvent>>,
}

impl RecordingDocEventLog {
    fn events(&self) -> Vec<RecordedDocEvent> {
        self.events.lock().unwrap().clone()
    }
}

type RecordedDocEvent = (Uuid, Uuid, String, Option<serde_json::Value>);

#[async_trait]
impl DocEventLog for RecordingDocEventLog {
    async fn append(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        event_type: &str,
        payload: Option<serde_json::Value>,
    ) -> PortResult<()> {
        self.events
            .lock()
            .unwrap()
            .push((workspace_id, doc_id, event_type.to_string(), payload));
        Ok(())
    }
}
