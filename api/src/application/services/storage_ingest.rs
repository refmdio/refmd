use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
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
use crate::application::services::documents::DocumentService;
use crate::application::services::errors::ServiceError;
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
    document_service: Arc<DocumentService>,
}

impl StorageIngestService {
    pub fn new(
        document_repo: Arc<dyn DocumentRepository>,
        files_repo: Arc<dyn FilesRepository>,
        realtime: Arc<dyn RealtimeEngine>,
        storage: Arc<dyn StoragePort>,
        events: Arc<dyn DocEventLog>,
        document_service: Arc<DocumentService>,
    ) -> Self {
        Self {
            document_repo,
            files_repo,
            realtime,
            storage,
            events,
            document_service,
        }
    }

    fn relative_path(user_id: Uuid, repo_path: &str) -> String {
        let trimmed = repo_path.trim_start_matches('/');
        format!("{}/{}", user_id, trimmed)
    }

    async fn handle_doc_upsert(
        &self,
        doc: &ResolvedDocument,
        event: &StorageIngestEvent,
        payload: MarkdownIngestPayload,
    ) -> anyhow::Result<()> {
        let snapshot = snapshot_from_markdown(&payload.body);
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
                    "content_hash": payload.content_hash,
                    "doc_type": doc.doc_type,
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

    async fn load_markdown_payload(&self, rel_path: &str) -> anyhow::Result<MarkdownIngestPayload> {
        let abs = self.storage.absolute_from_relative(rel_path);
        let bytes = self.storage.read_bytes(abs.as_path()).await?;
        parse_markdown_payload(bytes)
    }

    async fn resolve_doc_from_front_matter(
        &self,
        user_id: Uuid,
        payload: &MarkdownIngestPayload,
    ) -> anyhow::Result<Option<ResolvedDocument>> {
        let Some(doc_id) = payload.doc_id_hint else {
            return Ok(None);
        };
        let Some(meta) = self
            .document_repo
            .get_meta_for_owner(doc_id, user_id)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(ResolvedDocument::new(
            doc_id,
            meta.doc_type,
            meta.path,
        )))
    }

    async fn handle_doc_delete(
        &self,
        doc: &ResolvedDocument,
        event: &StorageIngestEvent,
    ) -> anyhow::Result<()> {
        match self
            .document_service
            .delete_for_user(doc.id, event.user_id)
            .await
        {
            Ok(true) => {
                info!(
                    doc_id = %doc.id,
                    repo_path = event.repo_path,
                    backend = event.backend,
                    "storage_ingest_doc_delete_applied"
                );
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(ServiceError::NotFound) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    async fn reconcile_repo_path(&self, doc: &ResolvedDocument, owner_id: Uuid, rel_path: &str) {
        if doc.path.as_deref() == Some(rel_path) {
            return;
        }
        if let Err(err) = self
            .document_repo
            .update_repo_path(doc.id, owner_id, rel_path)
            .await
        {
            warn!(
                doc_id = %doc.id,
                error = ?err,
                "storage_ingest_repo_path_update_failed"
            );
        }
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
            .map(ResolvedDocument::from)
        {
            if doc.is_folder() {
                warn!(
                    doc_id = %doc.id,
                    repo_path = event.repo_path,
                    "storage_ingest_folder_event_skipped"
                );
                return Ok(());
            }
            match event.kind {
                StorageIngestKind::Upsert => {
                    let payload = self.load_markdown_payload(&rel_path).await?;
                    self.handle_doc_upsert(&doc, event, payload).await?;
                }
                StorageIngestKind::Delete => {
                    self.handle_doc_delete(&doc, event).await?;
                }
            }
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

        if event.kind == StorageIngestKind::Upsert && rel_path.ends_with(".md") {
            let payload = self.load_markdown_payload(&rel_path).await?;
            if let Some(doc) = self
                .resolve_doc_from_front_matter(event.user_id, &payload)
                .await?
            {
                if doc.is_folder() {
                    warn!(
                        doc_id = %doc.id,
                        repo_path = event.repo_path,
                        "storage_ingest_folder_event_skipped"
                    );
                } else {
                    self.reconcile_repo_path(&doc, event.user_id, &rel_path)
                        .await;
                    self.handle_doc_upsert(&doc, event, payload).await?;
                }
                return Ok(());
            }
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

#[derive(Debug, Clone)]
struct ResolvedDocument {
    id: Uuid,
    doc_type: String,
    path: Option<String>,
}

impl ResolvedDocument {
    fn new(id: Uuid, doc_type: String, path: Option<String>) -> Self {
        Self { id, doc_type, path }
    }

    fn is_folder(&self) -> bool {
        self.doc_type == "folder"
    }
}

impl From<DomainDocument> for ResolvedDocument {
    fn from(value: DomainDocument) -> Self {
        Self::new(value.id, value.doc_type, value.path)
    }
}

#[derive(Debug, Clone)]
struct MarkdownIngestPayload {
    doc_id_hint: Option<Uuid>,
    body: String,
    content_hash: String,
}

#[derive(Debug, Deserialize)]
struct MarkdownFrontMatter {
    id: Option<Uuid>,
}

fn parse_markdown_payload(bytes: Vec<u8>) -> anyhow::Result<MarkdownIngestPayload> {
    let content_hash = sha256_hex(&bytes);
    let text = String::from_utf8(bytes)?;
    let trimmed = text.trim_start_matches('\u{feff}');
    if let Some((front, body)) = split_front_matter(trimmed) {
        if let Ok(front_matter) = serde_yaml::from_str::<MarkdownFrontMatter>(front) {
            if let Some(doc_id) = front_matter.id {
                return Ok(MarkdownIngestPayload {
                    doc_id_hint: Some(doc_id),
                    body: body.to_string(),
                    content_hash,
                });
            }
        }
    }
    Ok(MarkdownIngestPayload {
        doc_id_hint: None,
        body: trimmed.to_string(),
        content_hash,
    })
}

fn split_front_matter(input: &str) -> Option<(&str, &str)> {
    let Some(after_open) = input
        .strip_prefix("---\r\n")
        .or_else(|| input.strip_prefix("---\n"))
    else {
        return None;
    };
    if let Some((front_len, body_start)) = find_front_matter_end(after_open) {
        let front = &after_open[..front_len];
        let body = &after_open[body_start..];
        return Some((front, body));
    }
    None
}

fn find_front_matter_end(s: &str) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'\n' {
            let after_newline = &s[idx + 1..];
            if after_newline.starts_with("---") {
                let mut body_start = idx + 1 + 3;
                let remainder = &s[body_start..];
                if remainder.starts_with("\r\n") {
                    body_start += 2;
                } else if remainder.starts_with('\n') {
                    body_start += 1;
                }
                return Some((idx, body_start));
            }
        }
        idx += 1;
    }
    None
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn preserves_body_when_front_matter_has_no_id() {
        let markdown = "---\ntitle: Foo\n---\n\nBody".to_string();
        let payload = parse_markdown_payload(markdown.clone().into_bytes()).unwrap();
        assert!(payload.doc_id_hint.is_none());
        assert_eq!(payload.body, markdown);
    }

    #[test]
    fn extracts_id_when_front_matter_is_valid() {
        let doc_id = Uuid::new_v4();
        let markdown = format!("---\nid: {}\n---\n\nHello", doc_id);
        let payload = parse_markdown_payload(markdown.into_bytes()).unwrap();
        assert_eq!(payload.doc_id_hint, Some(doc_id));
        assert_eq!(payload.body.trim_start_matches('\n'), "Hello");
    }
}
