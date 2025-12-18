use std::sync::Arc;

use mime_guess::MimeGuess;
use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use crate::core::ports::storage::storage_port::StorageResolverPort;
use crate::core::services::access::{self, Actor};
use crate::core::services::errors::ServiceError;
use crate::documents::ports::access_repository::AccessRepository;
use crate::documents::ports::doc_event_log::DocEventLog;
use crate::documents::ports::files::files_repository::FilesRepository;
use crate::documents::ports::sharing::share_access_port::ShareAccessPort;
use crate::documents::use_cases::files::upload_file::{UploadFile, UploadedFile};
use domain::documents::path as doc_path;

pub struct FilePayload {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
}

pub struct FileService {
    files_repo: Arc<dyn FilesRepository>,
    storage: Arc<dyn StorageResolverPort>,
    access_repo: Arc<dyn AccessRepository>,
    share_access: Arc<dyn ShareAccessPort>,
    events: Arc<dyn DocEventLog>,
}

impl FileService {
    pub fn new(
        files_repo: Arc<dyn FilesRepository>,
        storage: Arc<dyn StorageResolverPort>,
        access_repo: Arc<dyn AccessRepository>,
        share_access: Arc<dyn ShareAccessPort>,
        events: Arc<dyn DocEventLog>,
    ) -> Self {
        Self {
            files_repo,
            storage,
            access_repo,
            share_access,
            events,
        }
    }

    pub async fn upload_file(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        doc_id: Uuid,
        bytes: Vec<u8>,
        orig_filename: Option<String>,
        content_type: Option<String>,
        public_base_url: Option<String>,
    ) -> Result<UploadedFile, ServiceError> {
        let uc = UploadFile {
            repo: self.files_repo.as_ref(),
            storage: self.storage.as_ref(),
            public_base_url,
        };
        let uploaded = uc
            .execute(workspace_id, doc_id, bytes, orig_filename, content_type)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::Forbidden)?;
        self.emit_attachment_upsert(workspace_id, actor_id, doc_id, &uploaded)
            .await;
        Ok(uploaded)
    }

    pub async fn download_owned_file(
        &self,
        workspace_id: Uuid,
        file_id: Uuid,
    ) -> Result<FilePayload, ServiceError> {
        let meta = self
            .files_repo
            .get_file_meta(file_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        if meta.workspace_id != workspace_id {
            return Err(ServiceError::Forbidden);
        }
        let abs_path = self.storage.absolute_from_relative(&meta.storage_path);
        let bytes = self
            .storage
            .read_bytes(&abs_path)
            .await
            .map_err(ServiceError::from)?;
        Ok(FilePayload {
            bytes,
            content_type: meta.content_type,
        })
    }

    pub async fn get_file_by_name(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        filename: &str,
    ) -> Result<FilePayload, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await?;

        let meta = self
            .files_repo
            .get_file_path_by_doc_and_name(doc_id, filename)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        let abs_path = self.storage.absolute_from_relative(&meta.storage_path);
        let bytes = self
            .storage
            .read_bytes(&abs_path)
            .await
            .map_err(ServiceError::from)?;
        Ok(FilePayload {
            bytes,
            content_type: meta.content_type,
        })
    }

    pub async fn serve_upload(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        attachment_path: &str,
    ) -> Result<FilePayload, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await?;

        let file_path = self
            .storage
            .resolve_upload_path(doc_id, attachment_path)
            .await
            .map_err(ServiceError::from)?;
        let bytes = self
            .storage
            .read_bytes(&file_path)
            .await
            .map_err(ServiceError::from)?;
        let guess = MimeGuess::from_path(&file_path);
        let content_type = Some(guess.first_or_octet_stream().essence_str().to_string());
        Ok(FilePayload {
            bytes,
            content_type,
        })
    }

    async fn emit_attachment_upsert(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        doc_id: Uuid,
        file: &UploadedFile,
    ) {
        let Some(repo_path) =
            doc_path::repo_relative_from_storage(workspace_id, &file.storage_path)
        else {
            return;
        };
        if let Err(err) = self
            .events
            .append(
                workspace_id,
                doc_id,
                "attachment.ingest_upsert",
                Some(json!({
                    "repo_path": repo_path.as_str(),
                    "storage_path": file.storage_path,
                    "backend": "api",
                    "size": file.size,
                    "content_hash": file.content_hash,
                    "workspace_id": workspace_id.to_string(),
                    "actor_id": actor_id.to_string(),
                })),
            )
            .await
        {
            warn!(
                document_id = %doc_id,
                error = ?err,
                "attachment_event_emit_failed"
            );
        }
    }
}
