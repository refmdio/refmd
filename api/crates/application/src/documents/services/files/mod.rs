use std::sync::Arc;

use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use crate::core::ports::storage::storage_port::StorageResolverPort;
use crate::core::services::access::{self, Actor};
use crate::core::services::errors::ServiceError;
use crate::documents::ports::access_repository::AccessRepository;
use crate::documents::ports::doc_event_log::DocEventLog;
pub use crate::documents::ports::files::files_repository::FileRecord;
use crate::documents::ports::files::files_repository::FilesRepository;
use crate::documents::ports::sharing::share_access_port::ShareAccessPort;
use crate::documents::use_cases::files::upload_file::{FileUploadInput, UploadFile, UploadedFile};
use async_trait::async_trait;
use domain::documents::path as doc_path;

/// File payload with optional E2EE metadata
pub struct FilePayload {
    /// File bytes (.rme format for E2EE files, raw bytes for legacy files)
    pub bytes: Vec<u8>,
    /// Encrypted file metadata (filename, content_type, etc.)
    /// None for legacy files uploaded before E2EE
    pub encrypted_metadata: Option<Vec<u8>>,
    /// Nonce for encrypted metadata
    /// None for legacy files uploaded before E2EE
    pub encrypted_metadata_nonce: Option<Vec<u8>>,
    /// Hash of encrypted content
    /// None for legacy files uploaded before E2EE
    pub encrypted_hash: Option<String>,
}

#[async_trait]
pub trait FileServiceFacade: Send + Sync {
    /// Upload an E2EE encrypted file.
    #[allow(clippy::too_many_arguments)]
    async fn upload_file(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        doc_id: Uuid,
        input: FileUploadInput,
        public_base_url: Option<String>,
    ) -> Result<UploadedFile, ServiceError>;

    /// Download file with E2EE metadata.
    async fn download_owned_file(
        &self,
        actor: &Actor,
        workspace_id: Uuid,
        file_id: Uuid,
    ) -> Result<FilePayload, ServiceError>;

    /// Serve file by storage path (for backwards compatibility with existing URLs).
    async fn serve_upload(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        attachment_path: &str,
    ) -> Result<FilePayload, ServiceError>;

    /// List files for a document (for building file map on client).
    async fn list_files_for_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<FileRecord>, ServiceError>;

    /// List files for a document with actor-based authorization.
    /// Used for share token access where workspace_id is not directly available.
    async fn list_files_for_actor(
        &self,
        actor: &Actor,
        doc_id: Uuid,
    ) -> Result<Vec<FileRecord>, ServiceError>;

    /// Download file with actor-based authorization.
    /// Used for share token access where workspace_id is not directly available.
    async fn download_file_for_actor(
        &self,
        actor: &Actor,
        file_id: Uuid,
    ) -> Result<FilePayload, ServiceError>;
}

#[async_trait]
impl FileServiceFacade for FileService {
    #[allow(clippy::too_many_arguments)]
    async fn upload_file(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        doc_id: Uuid,
        input: FileUploadInput,
        public_base_url: Option<String>,
    ) -> Result<UploadedFile, ServiceError> {
        self.upload_file(workspace_id, actor_id, doc_id, input, public_base_url)
            .await
    }

    async fn download_owned_file(
        &self,
        actor: &Actor,
        workspace_id: Uuid,
        file_id: Uuid,
    ) -> Result<FilePayload, ServiceError> {
        self.download_owned_file(actor, workspace_id, file_id).await
    }

    async fn serve_upload(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        attachment_path: &str,
    ) -> Result<FilePayload, ServiceError> {
        self.serve_upload(actor, doc_id, attachment_path).await
    }

    async fn list_files_for_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<FileRecord>, ServiceError> {
        self.list_files_for_document(workspace_id, doc_id).await
    }

    async fn list_files_for_actor(
        &self,
        actor: &Actor,
        doc_id: Uuid,
    ) -> Result<Vec<FileRecord>, ServiceError> {
        self.list_files_for_actor(actor, doc_id).await
    }

    async fn download_file_for_actor(
        &self,
        actor: &Actor,
        file_id: Uuid,
    ) -> Result<FilePayload, ServiceError> {
        self.download_file_for_actor(actor, file_id).await
    }
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

    /// Upload a file with optional E2EE metadata.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_file(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        doc_id: Uuid,
        input: FileUploadInput,
        public_base_url: Option<String>,
    ) -> Result<UploadedFile, ServiceError> {
        let uc = UploadFile {
            repo: self.files_repo.as_ref(),
            storage: self.storage.as_ref(),
            public_base_url,
        };
        let uploaded = uc
            .execute(workspace_id, doc_id, input)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::Forbidden)?;
        self.emit_attachment_upsert(workspace_id, actor_id, doc_id, &uploaded)
            .await;
        Ok(uploaded)
    }

    /// Download file with E2EE metadata.
    pub async fn download_owned_file(
        &self,
        actor: &Actor,
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
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            meta.document_id,
        )
        .await?;
        let abs_path = self.storage.absolute_from_relative(&meta.storage_path);
        let bytes = self
            .storage
            .read_bytes(&abs_path)
            .await
            .map_err(ServiceError::from)?;
        Ok(FilePayload {
            bytes,
            encrypted_metadata: meta.encrypted_metadata,
            encrypted_metadata_nonce: meta.encrypted_metadata_nonce,
            encrypted_hash: meta.encrypted_hash,
        })
    }

    /// Serve file by storage path.
    /// For E2EE files, returns encrypted bytes with metadata headers.
    /// For legacy files, returns raw bytes with None for E2EE fields.
    /// Returns encrypted file with E2EE metadata.
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

        // Get the relative path to look up file record
        let relative_path = self.storage.relative_from_uploads(&file_path);

        // Look up file record by storage path to get encrypted metadata
        let scope = self
            .files_repo
            .find_by_storage_path(&relative_path)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        // Get full file metadata
        let meta = self
            .files_repo
            .get_file_meta(scope.file_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        let bytes = self
            .storage
            .read_bytes(&file_path)
            .await
            .map_err(ServiceError::from)?;

        Ok(FilePayload {
            bytes,
            encrypted_metadata: meta.encrypted_metadata,
            encrypted_metadata_nonce: meta.encrypted_metadata_nonce,
            encrypted_hash: meta.encrypted_hash,
        })
    }

    /// List files for a document (for building file map on client).
    pub async fn list_files_for_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<FileRecord>, ServiceError> {
        // Verify document belongs to workspace
        let is_workspace_doc = self
            .files_repo
            .is_workspace_document(doc_id, workspace_id)
            .await
            .map_err(ServiceError::from)?;
        if !is_workspace_doc {
            return Err(ServiceError::Forbidden);
        }
        let files = self
            .files_repo
            .list_files_for_document(doc_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(files)
    }

    /// List files for a document with actor-based authorization.
    /// Used for share token access where workspace_id is not directly available.
    pub async fn list_files_for_actor(
        &self,
        actor: &Actor,
        doc_id: Uuid,
    ) -> Result<Vec<FileRecord>, ServiceError> {
        // Verify actor has view access to the document
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await?;

        let files = self
            .files_repo
            .list_files_for_document(doc_id)
            .await
            .map_err(ServiceError::from)?;
        Ok(files)
    }

    /// Download file with actor-based authorization.
    /// Used for share token access where workspace_id is not directly available.
    pub async fn download_file_for_actor(
        &self,
        actor: &Actor,
        file_id: Uuid,
    ) -> Result<FilePayload, ServiceError> {
        let meta = self
            .files_repo
            .get_file_meta(file_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        // Verify actor has view access to the document
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            meta.document_id,
        )
        .await?;

        let abs_path = self.storage.absolute_from_relative(&meta.storage_path);
        let bytes = self
            .storage
            .read_bytes(&abs_path)
            .await
            .map_err(ServiceError::from)?;
        Ok(FilePayload {
            bytes,
            encrypted_metadata: meta.encrypted_metadata,
            encrypted_metadata_nonce: meta.encrypted_metadata_nonce,
            encrypted_hash: meta.encrypted_hash,
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
                    "encrypted_hash": file.encrypted_hash,
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
