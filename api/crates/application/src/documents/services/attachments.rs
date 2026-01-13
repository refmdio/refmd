use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use domain::documents::document::Document as DomainDocument;
use domain::documents::path as doc_path;

use crate::core::services::errors::ServiceError;
use crate::core::services::utils::hash::sha256_hex;

use super::DocumentService;

/// Snapshot of an encrypted attachment for document duplication.
/// All fields contain encrypted data from the original file.
#[derive(Debug, Clone)]
pub(super) struct AttachmentSnapshot {
    /// Encrypted file bytes (.rme format)
    bytes: Vec<u8>,
    /// Encrypted file metadata
    encrypted_metadata: Vec<u8>,
    /// Nonce for encrypted metadata
    encrypted_metadata_nonce: Vec<u8>,
    /// Hash of encrypted content
    encrypted_hash: String,
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
            // Skip legacy files without E2EE metadata
            let (Some(encrypted_metadata), Some(encrypted_metadata_nonce), Some(encrypted_hash)) =
                (file.encrypted_metadata, file.encrypted_metadata_nonce, file.encrypted_hash)
            else {
                warn!(
                    document_id = %doc_id,
                    storage_path = %file.storage_path,
                    "duplicate_attachment_skipped_legacy"
                );
                continue;
            };
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
            snapshots.push(AttachmentSnapshot {
                bytes,
                encrypted_metadata,
                encrypted_metadata_nonce,
                encrypted_hash,
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
            .build_doc_dir(target_doc.id())
            .await
            .map_err(ServiceError::from)?;
        for attachment in attachments {
            // Use UUID for storage filename (E2EE - no plaintext filename)
            let file_uuid = Uuid::new_v4();
            let target_path = base_dir.join("attachments").join(file_uuid.to_string());
            self.storage
                .write_bytes(&target_path, &attachment.bytes)
                .await
                .map_err(ServiceError::from)?;
            let storage_path = self
                .storage
                .relative_from_uploads(&target_path)
                .replace('\\', "/");
            self.files_repo
                .insert_file(crate::documents::ports::files::files_repository::FileInsert {
                    doc_id: target_doc.id(),
                    size: attachment.bytes.len() as i64,
                    storage_path: &storage_path,
                    encrypted_metadata: &attachment.encrypted_metadata,
                    encrypted_metadata_nonce: &attachment.encrypted_metadata_nonce,
                    encrypted_hash: &attachment.encrypted_hash,
                })
                .await
                .map_err(ServiceError::from)?;
            if let Some(repo_path) =
                doc_path::repo_relative_from_storage(target_doc.workspace_id(), &storage_path)
            {
                let payload = json!({
                    "repo_path": repo_path.as_str(),
                    "storage_path": storage_path,
                    "backend": "api",
                    "size": attachment.bytes.len() as i64,
                    "encrypted_hash": attachment.encrypted_hash,
                    "workspace_id": target_doc.workspace_id().to_string(),
                    "actor_id": actor_id.to_string(),
                });
                self.record_event(
                    target_doc.workspace_id(),
                    target_doc.id(),
                    "attachment.ingest_upsert",
                    Some(payload),
                )
                .await;
            }
        }
        Ok(())
    }
}

fn _hash_bytes(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}
