use uuid::Uuid;

use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::storage_port::StoragePort;

pub struct UploadFile<'a, R, S>
where
    R: FilesRepository + ?Sized,
    S: StoragePort + ?Sized,
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
}

impl<'a, R, S> UploadFile<'a, R, S>
where
    R: FilesRepository + ?Sized,
    S: StoragePort + ?Sized,
{
    pub async fn execute(
        &self,
        owner_id: Uuid,
        doc_id: Uuid,
        bytes: Vec<u8>,
        orig_filename: Option<String>,
        content_type: Option<String>,
    ) -> anyhow::Result<Option<UploadedFile>> {
        if !self.repo.is_owner_document(doc_id, owner_id).await? {
            return Ok(None);
        }
        let stored = self
            .storage
            .store_doc_attachment(doc_id, orig_filename.as_deref(), &bytes)
            .await
            .map_err(|err| {
                tracing::error!(error = ?err, doc_id = %doc_id, "store_doc_attachment_failed");
                err
            })?;
        let id = self
            .repo
            .insert_file(
                doc_id,
                &stored.filename,
                content_type.as_deref(),
                stored.size,
                &stored.relative_path,
                &stored.content_hash,
            )
            .await
            .map_err(|err| {
                tracing::error!(error = ?err, doc_id = %doc_id, "insert_file_failed");
                err
            })?;
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
            content_type,
            size: stored.size,
        }))
    }
}
