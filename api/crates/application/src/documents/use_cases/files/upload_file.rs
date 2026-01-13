use uuid::Uuid;

use crate::core::ports::storage::storage_port::StorageResolverPort;
use crate::documents::ports::files::files_repository::{FileInsert, FilesRepository};

pub struct UploadFile<'a, R, S>
where
    R: FilesRepository + ?Sized,
    S: StorageResolverPort + ?Sized,
{
    pub repo: &'a R,
    pub storage: &'a S,
    pub public_base_url: Option<String>,
}

pub struct UploadedFile {
    pub id: Uuid,
    pub url: String,
    pub size: i64,
    pub storage_path: String,
    /// Encrypted file metadata (filename, content_type, etc.)
    pub encrypted_metadata: Vec<u8>,
    /// Nonce for encrypted metadata
    pub encrypted_metadata_nonce: Vec<u8>,
    /// Hash of encrypted content
    pub encrypted_hash: String,
}

/// Input for file upload (E2EE encrypted)
pub struct FileUploadInput {
    /// Encrypted file bytes (.rme format)
    pub bytes: Vec<u8>,
    /// Encrypted file metadata (filename, content_type, etc.)
    pub encrypted_metadata: Vec<u8>,
    /// Nonce for encrypted metadata
    pub encrypted_metadata_nonce: Vec<u8>,
    /// Hash of encrypted content (for deduplication/verification)
    pub encrypted_hash: String,
}

impl<'a, R, S> UploadFile<'a, R, S>
where
    R: FilesRepository + ?Sized,
    S: StorageResolverPort + ?Sized,
{
    /// Upload an E2EE encrypted file.
    /// All files are encrypted - filename and content_type are stored in encrypted_metadata.
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        input: FileUploadInput,
    ) -> anyhow::Result<Option<UploadedFile>> {
        if !self
            .repo
            .is_workspace_document(doc_id, workspace_id)
            .await?
        {
            return Ok(None);
        }
        // Store with None for original_filename - we use UUID for storage path
        let stored = self
            .storage
            .store_doc_attachment(doc_id, None, &input.bytes)
            .await
            .map_err(|err| {
                tracing::error!(error = ?err, doc_id = %doc_id, "store_doc_attachment_failed");
                err
            })?;
        let id = self
            .repo
            .insert_file(FileInsert {
                doc_id,
                size: stored.size,
                storage_path: &stored.relative_path,
                encrypted_metadata: &input.encrypted_metadata,
                encrypted_metadata_nonce: &input.encrypted_metadata_nonce,
                encrypted_hash: &input.encrypted_hash,
            })
            .await
            .map_err(|err| {
                tracing::error!(error = ?err, doc_id = %doc_id, "insert_file_failed");
                err
            })?;
        let storage_path = stored.relative_path.clone();
        // URL format: /api/uploads/{doc_id}/attachments/{filename}
        // This matches what serve_upload expects (doc_id as first segment)
        let url = if let Some(base) = self.public_base_url.as_deref() {
            let origin = base.trim_end_matches('/');
            format!(
                "{}/api/uploads/{}/attachments/{}",
                origin, doc_id, stored.filename
            )
        } else {
            format!("/api/uploads/{}/attachments/{}", doc_id, stored.filename)
        };
        Ok(Some(UploadedFile {
            id,
            url,
            size: stored.size,
            storage_path,
            encrypted_metadata: input.encrypted_metadata,
            encrypted_metadata_nonce: input.encrypted_metadata_nonce,
            encrypted_hash: input.encrypted_hash,
        }))
    }
}
