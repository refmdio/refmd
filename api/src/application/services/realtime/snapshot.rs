use std::sync::Arc;

use uuid::Uuid;
use yrs::{Doc, GetString, ReadTxn, StateVector, Transact};

use crate::application::linkgraph;
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
}

pub struct SnapshotPersistOptions {
    pub clear_updates: bool,
    pub prune_snapshots: Option<i64>,
    pub prune_updates_before: Option<i64>,
}

impl Default for SnapshotPersistOptions {
    fn default() -> Self {
        Self {
            clear_updates: false,
            prune_snapshots: None,
            prune_updates_before: None,
        }
    }
}

pub struct SnapshotPersistResult {
    pub version: i64,
}

pub struct MarkdownPersistResult {
    pub written: bool,
}

impl SnapshotService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state_reader: Arc<dyn DocStateReader>,
        persistence: Arc<dyn DocPersistencePort>,
        storage: Arc<dyn StoragePort>,
        linkgraph_repo: Arc<dyn LinkGraphRepository>,
        tagging_repo: Arc<dyn TaggingRepository>,
    ) -> Self {
        Self {
            state_reader,
            persistence,
            storage,
            linkgraph_repo,
            tagging_repo,
        }
    }

    pub async fn persist_snapshot(
        &self,
        doc_id: &Uuid,
        doc: &Doc,
        options: SnapshotPersistOptions,
    ) -> anyhow::Result<SnapshotPersistResult> {
        let snapshot_bin = {
            let txn = doc.transact();
            txn.encode_state_as_update_v1(&StateVector::default())
        };
        let current_version = self
            .persistence
            .latest_snapshot_version(doc_id)
            .await?
            .unwrap_or(0);
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
        let _ = self.storage.sync_doc_paths(*doc_id).await;
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
}

fn extract_markdown(doc: &Doc) -> String {
    let txt = doc.get_or_insert_text("content");
    let txn = doc.transact();
    let contents = txt.get_string(&txn);
    contents
}
