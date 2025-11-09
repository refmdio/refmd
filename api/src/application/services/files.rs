use std::sync::Arc;

use mime_guess::MimeGuess;
use uuid::Uuid;

use crate::application::access::{self, Actor};
use crate::application::ports::access_repository::AccessRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::share_access_port::ShareAccessPort;
use crate::application::ports::storage_port::StoragePort;
use crate::application::services::errors::ServiceError;
use crate::application::use_cases::files::upload_file::{UploadFile, UploadedFile};

pub struct FilePayload {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
}

pub struct FileService {
    files_repo: Arc<dyn FilesRepository>,
    storage: Arc<dyn StoragePort>,
    access_repo: Arc<dyn AccessRepository>,
    share_access: Arc<dyn ShareAccessPort>,
}

impl FileService {
    pub fn new(
        files_repo: Arc<dyn FilesRepository>,
        storage: Arc<dyn StoragePort>,
        access_repo: Arc<dyn AccessRepository>,
        share_access: Arc<dyn ShareAccessPort>,
    ) -> Self {
        Self {
            files_repo,
            storage,
            access_repo,
            share_access,
        }
    }

    pub async fn upload_file(
        &self,
        user_id: Uuid,
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
        uc.execute(user_id, doc_id, bytes, orig_filename, content_type)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::Forbidden)
    }

    pub async fn download_owned_file(
        &self,
        owner_id: Uuid,
        file_id: Uuid,
    ) -> Result<FilePayload, ServiceError> {
        let meta = self
            .files_repo
            .get_file_meta(file_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        let (path, content_type, stored_owner) = meta;
        if stored_owner != owner_id {
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
}
