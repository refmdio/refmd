use std::sync::Arc;

use async_trait::async_trait;
use tracing::warn;
use uuid::Uuid;
use yrs::updates::decoder::Decode;
use yrs::{Doc, GetString, ReadTxn, StateVector, Text, Transact, Update};

use crate::core::ports::storage::storage_projection_queue::{
    StorageProjectionJobKind, StorageProjectionQueue,
};
use crate::core::services::utils::hash::sha256_hex;
use crate::documents::ports::document_snapshot_archive_repository::{
    DocumentSnapshotArchiveRepository, SnapshotArchiveEntry, SnapshotArchiveInsert,
    SnapshotArchiveRecord,
};
use crate::documents::ports::linkgraph_repository::LinkGraphRepository;
use crate::documents::ports::realtime::realtime_hydration_port::DocStateReader;
use crate::documents::ports::realtime::realtime_persistence_port::DocPersistencePort;
use crate::documents::ports::realtime::realtime_persistence_port::SnapshotEntry;
use crate::documents::services::linkgraph;
use domain::documents::doc_type::DocumentType;

pub struct SnapshotService {
    state_reader: Arc<dyn DocStateReader>,
    persistence: Arc<dyn DocPersistencePort>,
    linkgraph_repo: Arc<dyn LinkGraphRepository>,
    archive_repo: Arc<dyn DocumentSnapshotArchiveRepository>,
    storage_jobs: Arc<dyn StorageProjectionQueue>,
}

#[derive(Default)]
pub struct SnapshotPersistOptions {
    pub clear_updates: bool,
    pub skip_if_unchanged: bool,
    pub prune_snapshots: Option<i64>,
    pub prune_updates_before: Option<i64>,
}

pub struct SnapshotPersistResult {
    pub version: i64,
    pub snapshot_bytes: Vec<u8>,
    pub persisted: bool,
}

pub struct MarkdownPersistResult {
    pub written: bool,
}

pub struct MarkdownExport {
    pub bytes: Vec<u8>,
    pub repo_path: Option<String>,
    pub owner_id: Option<Uuid>,
    pub workspace_id: Uuid,
    pub content_hash: String,
}

#[async_trait]
pub trait MarkdownExportProvider: Send + Sync {
    async fn export_markdown_for_doc(
        &self,
        doc_id: &Uuid,
    ) -> anyhow::Result<Option<MarkdownExport>>;
}

#[async_trait]
impl MarkdownExportProvider for SnapshotService {
    async fn export_markdown_for_doc(
        &self,
        doc_id: &Uuid,
    ) -> anyhow::Result<Option<MarkdownExport>> {
        self.export_current_markdown(doc_id).await
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SnapshotArchiveKind {
    Manual,
    Automatic,
    Restore,
}

impl SnapshotArchiveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SnapshotArchiveKind::Manual => "manual",
            SnapshotArchiveKind::Automatic => "auto",
            SnapshotArchiveKind::Restore => "restore",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotArchiveOptions<'a> {
    pub label: &'a str,
    pub notes: Option<&'a str>,
    pub kind: SnapshotArchiveKind,
    pub created_by: Option<&'a Uuid>,
}

impl SnapshotService {
    pub fn new(
        state_reader: Arc<dyn DocStateReader>,
        persistence: Arc<dyn DocPersistencePort>,
        linkgraph_repo: Arc<dyn LinkGraphRepository>,
        archive_repo: Arc<dyn DocumentSnapshotArchiveRepository>,
        storage_jobs: Arc<dyn StorageProjectionQueue>,
    ) -> Self {
        Self {
            state_reader,
            persistence,
            linkgraph_repo,
            archive_repo,
            storage_jobs,
        }
    }

    pub async fn persist_snapshot(
        &self,
        doc_id: &Uuid,
        doc: &Doc,
        options: SnapshotPersistOptions,
    ) -> anyhow::Result<SnapshotPersistResult> {
        let snapshot_bin = encode_doc_snapshot(doc);
        let (current_version, previous_snapshot) = if options.skip_if_unchanged {
            match self.persistence.latest_snapshot_entry(doc_id).await? {
                Some(SnapshotEntry { version, bytes, .. }) => (version, Some(bytes)),
                None => (0, None),
            }
        } else {
            (
                self.persistence
                    .latest_snapshot_version(doc_id)
                    .await?
                    .unwrap_or(0),
                None,
            )
        };

        if options.skip_if_unchanged
            && let Some(prev) = previous_snapshot.as_ref()
            && prev.as_slice() == snapshot_bin.as_slice()
        {
            if options.clear_updates {
                self.persistence.clear_updates(doc_id).await?;
            }
            if let Some(keep) = options.prune_snapshots {
                self.persistence.prune_snapshots(doc_id, keep).await?;
            }
            if let Some(cutoff) = options.prune_updates_before {
                self.persistence
                    .prune_updates_before(doc_id, cutoff)
                    .await?;
            }
            return Ok(SnapshotPersistResult {
                version: current_version,
                snapshot_bytes: snapshot_bin,
                persisted: false,
            });
        }
        let next_version = current_version + 1;
        self.persistence
            .persist_snapshot(doc_id, next_version, &snapshot_bin, None)
            .await?;
        if options.clear_updates {
            self.persistence.clear_updates(doc_id).await?;
        }
        if let Some(keep) = options.prune_snapshots {
            self.persistence.prune_snapshots(doc_id, keep).await?;
        }
        if let Some(cutoff) = options.prune_updates_before {
            self.persistence
                .prune_updates_before(doc_id, cutoff)
                .await?;
        }
        Ok(SnapshotPersistResult {
            version: next_version,
            snapshot_bytes: snapshot_bin,
            persisted: true,
        })
    }

    pub async fn write_markdown(
        &self,
        doc_id: &Uuid,
        doc: &Doc,
    ) -> anyhow::Result<MarkdownPersistResult> {
        let record = match self.state_reader.document_record(doc_id).await? {
            Some(r) => r,
            None => return Ok(MarkdownPersistResult { written: false }),
        };
        if record.doc_type == DocumentType::Folder {
            return Ok(MarkdownPersistResult { written: false });
        }
        let contents = extract_markdown(doc);
        if let Err(err) = self
            .storage_jobs
            .enqueue_doc_job(
                record.workspace_id,
                *doc_id,
                StorageProjectionJobKind::DocSync,
                Some("snapshot_write_markdown"),
            )
            .await
        {
            warn!(document_id = %doc_id, error = ?err, "enqueue_snapshot_projection_failed");
        }
        if let Some(owner_id) = record.owner_id {
            let _ = linkgraph::update_document_links(
                self.linkgraph_repo.as_ref(),
                owner_id,
                *doc_id,
                &contents,
            )
            .await;
            // Note: Automatic tag extraction removed (Phase 14 E2EE)
            // Tags are now extracted and encrypted on the client side
        }
        Ok(MarkdownPersistResult { written: true })
    }

    pub async fn export_current_markdown(
        &self,
        doc_id: &Uuid,
    ) -> anyhow::Result<Option<MarkdownExport>> {
        let Some(record) = self.state_reader.document_record(doc_id).await? else {
            return Ok(None);
        };
        if record.doc_type == DocumentType::Folder {
            return Ok(None);
        }
        let doc = self.hydrate_doc_from_state(doc_id).await?;
        let contents = extract_markdown(&doc);
        let bytes = render_markdown_bytes(doc_id, &record.title, &contents);
        let content_hash = sha256_hex(&bytes);
        let repo_path = repo_path_from_record(&record);
        Ok(Some(MarkdownExport {
            bytes,
            repo_path,
            owner_id: record.owner_id,
            workspace_id: record.workspace_id,
            content_hash,
        }))
    }

    pub async fn archive_snapshot(
        &self,
        doc_id: &Uuid,
        snapshot_bin: &[u8],
        version: i64,
        options: SnapshotArchiveOptions<'_>,
    ) -> anyhow::Result<SnapshotArchiveRecord> {
        let byte_size = snapshot_bin.len() as i64;
        let hash = sha256_hex(snapshot_bin);
        let record = self
            .archive_repo
            .insert(SnapshotArchiveInsert {
                document_id: doc_id,
                version,
                snapshot: snapshot_bin,
                label: options.label,
                notes: options.notes,
                kind: options.kind.as_str(),
                created_by: options.created_by,
                byte_size,
                content_hash: &hash,
            })
            .await?;
        Ok(record)
    }

    pub async fn list_archives(
        &self,
        doc_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<SnapshotArchiveRecord>> {
        self.archive_repo
            .list_for_document(doc_id, limit, offset)
            .await
            .map_err(Into::into)
    }

    pub async fn load_archive_doc(
        &self,
        archive_id: Uuid,
    ) -> anyhow::Result<Option<(SnapshotArchiveRecord, Doc)>> {
        let Some(entry) = self.archive_repo.get_by_id(archive_id).await? else {
            return Ok(None);
        };
        let doc = Doc::new();
        apply_update_bytes(&doc, &entry.bytes)?;
        Ok(Some((entry.record, doc)))
    }

    pub async fn load_archive_markdown(
        &self,
        archive_id: Uuid,
    ) -> anyhow::Result<Option<(SnapshotArchiveRecord, String)>> {
        if let Some((record, doc)) = self.load_archive_doc(archive_id).await? {
            let markdown = extract_markdown(&doc);
            return Ok(Some((record, markdown)));
        }
        Ok(None)
    }

    pub async fn load_previous_archive_markdown(
        &self,
        doc_id: Uuid,
        version: i64,
    ) -> anyhow::Result<Option<(SnapshotArchiveRecord, String)>> {
        if let Some(entry) = self.archive_repo.latest_before(doc_id, version).await? {
            let doc = Doc::new();
            apply_update_bytes(&doc, &entry.bytes)?;
            let markdown = extract_markdown(&doc);
            return Ok(Some((entry.record, markdown)));
        }
        Ok(None)
    }

    /// Get a snapshot entry (record + bytes) by ID
    pub async fn get_snapshot_entry(
        &self,
        snapshot_id: Uuid,
    ) -> anyhow::Result<Option<SnapshotArchiveEntry>> {
        self.archive_repo
            .get_by_id(snapshot_id)
            .await
            .map_err(Into::into)
    }
}

fn extract_markdown(doc: &Doc) -> String {
    let txt = doc.get_or_insert_text("content");
    let txn = doc.transact();
    txt.get_string(&txn)
}

fn render_markdown_bytes(doc_id: &Uuid, title: &str, contents: &str) -> Vec<u8> {
    let mut formatted = format!("---\nid: {}\ntitle: {}\n---\n\n{}", doc_id, title, contents);
    if !formatted.ends_with('\n') {
        formatted.push('\n');
    }
    formatted.into_bytes()
}

fn apply_update_bytes(doc: &Doc, bytes: &[u8]) -> anyhow::Result<()> {
    let update = Update::decode_v1(bytes)?;
    let mut txn = doc.transact_mut();
    txn.apply_update(update)?;
    Ok(())
}

pub fn encode_doc_snapshot(doc: &Doc) -> Vec<u8> {
    let txn = doc.transact();
    txn.encode_state_as_update_v1(&StateVector::default())
}

pub fn snapshot_from_markdown(content: &str) -> Vec<u8> {
    let doc = Doc::new();
    let text = doc.get_or_insert_text("content");
    let mut txn = doc.transact_mut();
    let len = text.len(&txn);
    if len > 0 {
        text.remove_range(&mut txn, 0, len);
    }
    if !content.is_empty() {
        text.insert(&mut txn, 0, content);
    }
    drop(txn);
    encode_doc_snapshot(&doc)
}

pub fn doc_from_snapshot_bytes(bytes: &[u8]) -> anyhow::Result<Doc> {
    let doc = Doc::new();
    apply_update_bytes(&doc, bytes)?;
    Ok(doc)
}

impl SnapshotService {
    async fn hydrate_doc_from_state(&self, doc_id: &Uuid) -> anyhow::Result<Doc> {
        let doc = Doc::new();
        let mut last_seq = 0i64;
        if let Some(snapshot) = self.state_reader.latest_snapshot(doc_id).await? {
            apply_update_bytes(&doc, &snapshot.snapshot)?;
            last_seq = snapshot.version;
        }
        let updates = self.state_reader.updates_since(doc_id, last_seq).await?;
        for update in updates {
            apply_update_bytes(&doc, &update.update)?;
        }
        Ok(doc)
    }
}

fn repo_path_from_record(
    record: &crate::documents::ports::realtime::realtime_hydration_port::DocumentRecord,
) -> Option<String> {
    if let Some(path) = record.desired_path.as_deref() {
        return Some(normalize_repo_path(path));
    }
    if let Some(path) = record.path.as_deref() {
        return strip_workspace_prefix(record.workspace_id, path);
    }
    None
}

fn strip_workspace_prefix(workspace_id: Uuid, relative: &str) -> Option<String> {
    let trimmed = relative.trim_start_matches('/');
    let mut parts = trimmed.splitn(2, '/');
    let owner = parts.next()?;
    if owner != workspace_id.to_string() {
        return None;
    }
    parts
        .next()
        .map(|rest| rest.trim_start_matches('/').to_string())
        .filter(|s| !s.is_empty())
}

fn normalize_repo_path(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        "".into()
    } else {
        trimmed.replace('\\', "/")
    }
}
