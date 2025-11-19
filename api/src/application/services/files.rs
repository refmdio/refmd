use std::sync::Arc;

use mime_guess::MimeGuess;
use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use crate::application::access::{self, Actor};
use crate::application::ports::access_repository::AccessRepository;
use crate::application::ports::doc_event_log::DocEventLog;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::share_access_port::ShareAccessPort;
use crate::application::ports::storage_port::StorageResolverPort;
use crate::application::services::errors::ServiceError;
use crate::application::use_cases::files::upload_file::{UploadFile, UploadedFile};

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
        let (path, content_type, stored_workspace) = meta;
        if stored_workspace != workspace_id {
            return Err(ServiceError::Forbidden);
        }
        let abs_path = self.storage.absolute_from_relative(&path);
        let bytes = self
            .storage
            .read_bytes(&abs_path)
            .await
            .map_err(ServiceError::from)?;
        Ok(FilePayload {
            bytes,
            content_type,
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
        .await
        .map_err(|_| ServiceError::Forbidden)?;

        let (path, ct) = self
            .files_repo
            .get_file_path_by_doc_and_name(doc_id, filename)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        let abs_path = self.storage.absolute_from_relative(&path);
        let bytes = self
            .storage
            .read_bytes(&abs_path)
            .await
            .map_err(ServiceError::from)?;
        Ok(FilePayload {
            bytes,
            content_type: ct,
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
        .await
        .map_err(|_| ServiceError::Unauthorized)?;

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
        let Some(repo_path) = repo_relative_from_storage(workspace_id, &file.storage_path) else {
            return;
        };
        if let Err(err) = self
            .events
            .append(
                workspace_id,
                doc_id,
                "attachment.ingest_upsert",
                Some(json!({
                    "repo_path": repo_path,
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

fn repo_relative_from_storage(workspace_id: Uuid, storage_path: &str) -> Option<String> {
    let trimmed = storage_path.trim_start_matches('/');
    let owner_prefix = workspace_id.to_string();
    let remainder = trimmed
        .strip_prefix(&owner_prefix)
        .map(|rest| rest.trim_start_matches('/'))
        .unwrap_or(trimmed);
    if remainder.is_empty() {
        None
    } else {
        Some(remainder.to_string())
    }
}
