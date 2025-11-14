use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

use crate::application::ports::doc_event_log::DocEventLog;
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::realtime_port::RealtimeEngine;
use crate::application::ports::storage_ingest_queue::{StorageIngestEvent, StorageIngestKind};
use crate::application::ports::storage_port::StoragePort;
use crate::application::services::realtime::snapshot::snapshot_from_markdown;
use crate::domain::documents::document::Document as DomainDocument;

#[async_trait]
pub trait StorageIngestHandler: Send + Sync {
    async fn handle_event(&self, event: &StorageIngestEvent) -> anyhow::Result<()>;
}

pub struct StorageIngestService {
    document_repo: Arc<dyn DocumentRepository>,
    files_repo: Arc<dyn FilesRepository>,
    realtime: Arc<dyn RealtimeEngine>,
    storage: Arc<dyn StoragePort>,
    events: Arc<dyn DocEventLog>,
}

impl StorageIngestService {
    pub fn new(
        document_repo: Arc<dyn DocumentRepository>,
        files_repo: Arc<dyn FilesRepository>,
        realtime: Arc<dyn RealtimeEngine>,
        storage: Arc<dyn StoragePort>,
        events: Arc<dyn DocEventLog>,
    ) -> Self {
        Self {
            document_repo,
            files_repo,
            realtime,
            storage,
            events,
        }
    }

    fn relative_path(user_id: Uuid, repo_path: &str) -> String {
        let trimmed = repo_path.trim_start_matches('/');
        format!("{}/{}", user_id, trimmed)
    }

    async fn handle_doc_upsert(
        &self,
        doc: DomainDocument,
        rel_path: &str,
        event: &StorageIngestEvent,
    ) -> anyhow::Result<()> {
        let abs = self.storage.absolute_from_relative(rel_path);
        let bytes = self.storage.read_bytes(abs.as_path()).await?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let hash = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let markdown = String::from_utf8(bytes)?;
        let snapshot = snapshot_from_markdown(&markdown);
        self.realtime
            .apply_snapshot(&doc.id.to_string(), snapshot.as_slice())
            .await?;
        if let Err(err) = self.realtime.force_persist(&doc.id.to_string()).await {
            warn!(
                error = ?err,
                doc_id = %doc.id,
                "storage_ingest_force_persist_failed"
            );
        }
        self.events
            .append(
                doc.id,
                "document.ingest_upsert",
                Some(json!({
                    "repo_path": event.repo_path,
                    "backend": event.backend,
                    "content_hash": hash,
                })),
            )
            .await?;
        info!(
            doc_id = %doc.id,
            repo_path = event.repo_path,
            backend = event.backend,
            "storage_ingest_doc_upsert_applied"
        );
        Ok(())
    }

    async fn handle_attachment_upsert(
        &self,
        file_id: Uuid,
        doc_id: Uuid,
        rel_path: &str,
        event: &StorageIngestEvent,
    ) -> anyhow::Result<()> {
        let abs = self.storage.absolute_from_relative(rel_path);
        let bytes = self.storage.read_bytes(abs.as_path()).await?;
        let size = bytes.len() as i64;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let hash = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        self.files_repo
            .update_hash_and_size(file_id, size, &hash)
            .await?;
        self.events
            .append(
                doc_id,
                "attachment.ingest_upsert",
                Some(json!({
                    "repo_path": event.repo_path,
                    "storage_path": rel_path,
                    "backend": event.backend,
                    "size": size,
                    "content_hash": hash,
                })),
            )
            .await?;
        info!(
            doc_id = %doc_id,
            file_id = %file_id,
            repo_path = event.repo_path,
            backend = event.backend,
            "storage_ingest_attachment_upsert_applied"
        );
        Ok(())
    }

    async fn handle_attachment_delete(
        &self,
        file_id: Uuid,
        doc_id: Uuid,
        event: &StorageIngestEvent,
    ) -> anyhow::Result<()> {
        self.files_repo.delete_by_id(file_id).await?;
        self.events
            .append(
                doc_id,
                "attachment.ingest_delete",
                Some(json!({
                    "repo_path": event.repo_path,
                    "backend": event.backend,
                })),
            )
            .await?;
        info!(
            doc_id = %doc_id,
            file_id = %file_id,
            repo_path = event.repo_path,
            backend = event.backend,
            "storage_ingest_attachment_deleted"
        );
        Ok(())
    }
}

#[async_trait]
impl StorageIngestHandler for StorageIngestService {
    async fn handle_event(&self, event: &StorageIngestEvent) -> anyhow::Result<()> {
        let rel_path = Self::relative_path(event.user_id, &event.repo_path);

        if let Some(doc) = self
            .document_repo
            .get_by_owner_and_path(event.user_id, &rel_path)
            .await?
        {
            if event.kind == StorageIngestKind::Upsert {
                return self.handle_doc_upsert(doc, &rel_path, event).await;
            }
            self.events
                .append(
                    doc.id,
                    "document.ingest_delete_detected",
                    Some(json!({
                        "repo_path": event.repo_path,
                        "backend": event.backend
                    })),
                )
                .await?;
            return Ok(());
        }

        if let Some((file_id, doc_id, owner_id)) =
            self.files_repo.find_by_storage_path(&rel_path).await?
        {
            info!(
                doc_id = %doc_id,
                owner_id = %owner_id,
                repo_path = event.repo_path,
                "storage_ingest_attachment_detected"
            );
            match event.kind {
                StorageIngestKind::Upsert => {
                    self.handle_attachment_upsert(file_id, doc_id, &rel_path, event)
                        .await?;
                }
                StorageIngestKind::Delete => {
                    self.handle_attachment_delete(file_id, doc_id, event)
                        .await?;
                }
            }
            return Ok(());
        }

        if event.kind == StorageIngestKind::Delete {
            self.storage.delete_relative_path(&rel_path).await?;
            info!(
                user_id = %event.user_id,
                repo_path = event.repo_path,
                backend = event.backend,
                "storage_ingest_orphan_deleted"
            );
        } else {
            warn!(
                user_id = %event.user_id,
                repo_path = event.repo_path,
                backend = event.backend,
                "storage_ingest_no_target_found"
            );
        }
        Ok(())
    }
}
