use std::sync::Arc;

use sha2::{Digest, Sha256};
use uuid::Uuid;
use yrs::updates::decoder::Decode;
use yrs::{Doc, GetString, ReadTxn, StateVector, Text, Transact, Update};

use crate::application::linkgraph;
use crate::application::ports::document_snapshot_archive_repository::{
    DocumentSnapshotArchiveRepository, SnapshotArchiveInsert, SnapshotArchiveRecord,
};
use crate::application::ports::linkgraph_repository::LinkGraphRepository;
use crate::application::ports::realtime_hydration_port::DocStateReader;
use crate::application::ports::realtime_persistence_port::DocPersistencePort;
use crate::application::ports::storage_port::StoragePort;
use crate::application::ports::tagging_repository::TaggingRepository;
use crate::application::services::tagging;

pub struct SnapshotService {
    state_reader: Arc<dyn DocStateReader>,
    persistence: Arc<dyn DocPersistencePort>,
    storage: Arc<dyn StoragePort>,
    linkgraph_repo: Arc<dyn LinkGraphRepository>,
    tagging_repo: Arc<dyn TaggingRepository>,
    archive_repo: Arc<dyn DocumentSnapshotArchiveRepository>,
}

pub struct SnapshotPersistOptions {
    pub clear_updates: bool,
    pub skip_if_unchanged: bool,
    pub prune_snapshots: Option<i64>,
    pub prune_updates_before: Option<i64>,
}

impl Default for SnapshotPersistOptions {
    fn default() -> Self {
        Self {
            clear_updates: false,
            skip_if_unchanged: false,
            prune_snapshots: None,
            prune_updates_before: None,
        }
    }
}

pub struct SnapshotPersistResult {
    pub version: i64,
    pub snapshot_bytes: Vec<u8>,
    pub persisted: bool,
}

pub struct MarkdownPersistResult {
    pub written: bool,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state_reader: Arc<dyn DocStateReader>,
        persistence: Arc<dyn DocPersistencePort>,
        storage: Arc<dyn StoragePort>,
        linkgraph_repo: Arc<dyn LinkGraphRepository>,
        tagging_repo: Arc<dyn TaggingRepository>,
        archive_repo: Arc<dyn DocumentSnapshotArchiveRepository>,
    ) -> Self {
        Self {
            state_reader,
            persistence,
            storage,
            linkgraph_repo,
            tagging_repo,
            archive_repo,
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
                Some((version, bytes)) => (version, Some(bytes)),
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

        if options.skip_if_unchanged {
            if let Some(prev) = previous_snapshot.as_ref() {
                if prev.as_slice() == snapshot_bin.as_slice() {
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
            }
        }
        let next_version = current_version + 1;
        self.persistence
            .persist_snapshot(doc_id, next_version, &snapshot_bin)
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
        if record.doc_type == "folder" {
            return Ok(MarkdownPersistResult { written: false });
        }
        let contents = extract_markdown(doc);
        self.storage.sync_doc_paths(*doc_id).await?;
        let path = self.storage.build_doc_file_path(*doc_id).await?;
        let mut formatted = format!(
            "---\nid: {}\ntitle: {}\n---\n\n{}",
            doc_id, record.title, contents
        );
        if !formatted.ends_with('\n') {
            formatted.push('\n');
        }
        let bytes = formatted.into_bytes();
        let should_write = match self.storage.read_bytes(path.as_path()).await {
            Ok(existing) => existing != bytes,
            Err(_) => true,
        };
        if should_write {
            self.storage.write_bytes(path.as_path(), &bytes).await?;
        }
        if let Some(owner_id) = record.owner_id {
            let _ = linkgraph::update_document_links(
                self.linkgraph_repo.as_ref(),
                owner_id,
                *doc_id,
                &contents,
            )
            .await;
            let _ = tagging::update_document_tags(
                self.tagging_repo.as_ref(),
                *doc_id,
                owner_id,
                &contents,
            )
            .await;
        }
        Ok(MarkdownPersistResult {
            written: should_write,
        })
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
    }

    pub async fn load_archive_doc(
        &self,
        archive_id: Uuid,
    ) -> anyhow::Result<Option<(SnapshotArchiveRecord, Doc)>> {
        let Some((record, bytes)) = self.archive_repo.get_by_id(archive_id).await? else {
            return Ok(None);
        };
        let doc = Doc::new();
        apply_update_bytes(&doc, &bytes)?;
        Ok(Some((record, doc)))
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
        if let Some((record, bytes)) = self.archive_repo.latest_before(doc_id, version).await? {
            let doc = Doc::new();
            apply_update_bytes(&doc, &bytes)?;
            let markdown = extract_markdown(&doc);
            return Ok(Some((record, markdown)));
        }
        Ok(None)
    }
}

fn extract_markdown(doc: &Doc) -> String {
    let txt = doc.get_or_insert_text("content");
    let txn = doc.transact();
    let contents = txt.get_string(&txn);
    contents
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
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
