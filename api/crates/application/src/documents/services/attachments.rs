use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use domain::documents::document::Document as DomainDocument;
use domain::documents::path as doc_path;

use crate::core::services::errors::ServiceError;
use crate::core::services::utils::hash::sha256_hex;

use super::DocumentService;

#[derive(Debug, Clone)]
pub(super) struct AttachmentSnapshot {
    filename: String,
    content_type: Option<String>,
    bytes: Vec<u8>,
    content_hash: String,
}

impl DocumentService {
    pub(super) async fn snapshot_attachments(
        &self,
        doc_id: Uuid,
    ) -> Result<Vec<AttachmentSnapshot>, ServiceError> {
        let files = self
            .files_repo
            .list_files_for_document(doc_id)
            .await
            .map_err(ServiceError::from)?;
        let mut snapshots = Vec::new();
        for file in files {
            let abs_path = self.storage.absolute_from_relative(&file.storage_path);
            let exists = self
                .storage
                .exists(&abs_path)
                .await
                .map_err(ServiceError::from)?;
            if !exists {
                warn!(
                    document_id = %doc_id,
                    storage_path = %file.storage_path,
                    "duplicate_attachment_missing"
                );
                continue;
            }
            let bytes = self
                .storage
                .read_bytes(&abs_path)
                .await
                .map_err(ServiceError::from)?;
            let content_hash = hash_bytes(&bytes);
            snapshots.push(AttachmentSnapshot {
                filename: file.filename,
                content_type: file.content_type,
                bytes,
                content_hash,
            });
        }
        Ok(snapshots)
    }

    pub(super) async fn copy_attachments(
        &self,
        target_doc: &DomainDocument,
        attachments: &[AttachmentSnapshot],
        actor_id: Uuid,
    ) -> Result<(), ServiceError> {
        if attachments.is_empty() {
            return Ok(());
        }
        let base_dir = self
            .storage
            .build_doc_dir(target_doc.id)
            .await
            .map_err(ServiceError::from)?;
        for attachment in attachments {
            let filename = std::path::Path::new(&attachment.filename)
                .file_name()
                .and_then(|f| f.to_str())
                .map(str::to_string)
                .filter(|f| !f.is_empty())
                .unwrap_or_else(|| attachment.filename.clone());
            let target_path = base_dir.join("attachments").join(&filename);
            self.storage
                .write_bytes(&target_path, &attachment.bytes)
                .await
                .map_err(ServiceError::from)?;
            let storage_path = self
                .storage
                .relative_from_uploads(&target_path)
                .replace('\\', "/");
            self.files_repo
                .insert_file(
                    target_doc.id,
                    &filename,
                    attachment.content_type.as_deref(),
                    attachment.bytes.len() as i64,
                    &storage_path,
                    &attachment.content_hash,
                )
                .await
                .map_err(ServiceError::from)?;
            if let Some(repo_path) =
                doc_path::repo_relative_from_storage(target_doc.workspace_id, &storage_path)
            {
                let payload = json!({
                    "repo_path": repo_path.as_str(),
                    "storage_path": storage_path,
                    "backend": "api",
                    "size": attachment.bytes.len() as i64,
                    "content_hash": attachment.content_hash,
                    "workspace_id": target_doc.workspace_id.to_string(),
                    "actor_id": actor_id.to_string(),
                });
                self.record_event(
                    target_doc.workspace_id,
                    target_doc.id,
                    "attachment.ingest_upsert",
                    Some(payload),
                )
                .await;
            }
        }
        Ok(())
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}
