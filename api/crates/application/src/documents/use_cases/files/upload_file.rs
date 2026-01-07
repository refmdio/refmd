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
    pub filename: String,
    pub content_type: Option<String>,
    pub size: i64,
    pub storage_path: String,
    pub content_hash: String,
    // E2EE fields
    pub encrypted_metadata: Option<Vec<u8>>,
    pub encrypted_metadata_nonce: Option<Vec<u8>>,
    pub encrypted_hash: Option<String>,
}

/// Input for file upload (unified for both plaintext and E2EE)
pub struct FileUploadInput {
    pub bytes: Vec<u8>,
    pub orig_filename: Option<String>,
    pub content_type: Option<String>,
    /// E2EE: encrypted file metadata
    pub encrypted_metadata: Option<Vec<u8>>,
    /// E2EE: nonce for encrypted metadata
    pub encrypted_metadata_nonce: Option<Vec<u8>>,
    /// E2EE: encrypted hash of the file content
    pub encrypted_hash: Option<String>,
}

impl<'a, R, S> UploadFile<'a, R, S>
where
    R: FilesRepository + ?Sized,
    S: StorageResolverPort + ?Sized,
{
    /// Upload a file with optional E2EE metadata.
    /// For plaintext files: pass encrypted_* fields as None in FileUploadInput
    /// For E2EE files: pass encrypted_* fields with values
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
        let stored = self
            .storage
            .store_doc_attachment(doc_id, input.orig_filename.as_deref(), &input.bytes)
            .await
            .map_err(|err| {
                tracing::error!(error = ?err, doc_id = %doc_id, "store_doc_attachment_failed");
                err
            })?;
        let id = self
            .repo
            .insert_file(FileInsert {
                doc_id,
                filename: &stored.filename,
                content_type: input.content_type.as_deref(),
                size: stored.size,
                storage_path: &stored.relative_path,
                content_hash: &stored.content_hash,
                encrypted_metadata: input.encrypted_metadata.as_deref(),
                encrypted_metadata_nonce: input.encrypted_metadata_nonce.as_deref(),
                encrypted_hash: input.encrypted_hash.as_deref(),
            })
            .await
            .map_err(|err| {
                tracing::error!(error = ?err, doc_id = %doc_id, "insert_file_failed");
                err
            })?;
        let storage_path = stored.relative_path.clone();
        let relative = stored.relative_path.trim_start_matches('/');
        let url = if let Some(base) = self.public_base_url.as_deref() {
            let origin = base.trim_end_matches('/');
            format!("{}/api/uploads/{}", origin, relative)
        } else {
            format!("/api/uploads/{}", relative)
        };
        Ok(Some(UploadedFile {
            id,
            url,
            filename: stored.filename,
            content_type: input.content_type,
            size: stored.size,
            storage_path,
            content_hash: stored.content_hash,
            encrypted_metadata: input.encrypted_metadata,
            encrypted_metadata_nonce: input.encrypted_metadata_nonce,
            encrypted_hash: input.encrypted_hash,
        }))
    }
}
