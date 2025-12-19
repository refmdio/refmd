use uuid::Uuid;

use crate::core::services::access::Actor;
use crate::core::services::errors::ServiceError;
use crate::documents::dtos::{DocumentDownload, DocumentDownloadFormat};
use crate::documents::use_cases::download_document::{
    DownloadDocument as DownloadDocumentUseCase, FolderDownloadUnsupportedFormat,
};

use super::DocumentService;

impl DocumentService {
    pub async fn download_document(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        format: DocumentDownloadFormat,
    ) -> Result<DocumentDownload, ServiceError> {
        let uc = DownloadDocumentUseCase {
            documents: self.document_repo.as_ref(),
            files: self.files_repo.as_ref(),
            storage: self.storage.as_ref(),
            access: self.access_repo.as_ref(),
            shares: self.share_access.as_ref(),
            snapshot: self.snapshot_service.as_ref(),
            exporter: self.exporter.as_ref(),
        };
        uc.execute(actor, doc_id, format)
            .await
            .map_err(|err| {
                if err
                    .downcast_ref::<FolderDownloadUnsupportedFormat>()
                    .is_some()
                {
                    ServiceError::BadRequest("folder_archive_only")
                } else {
                    ServiceError::from(err)
                }
            })?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn download_workspace_root(
        &self,
        actor: &Actor,
        workspace_id: Uuid,
        workspace_name: &str,
        format: DocumentDownloadFormat,
    ) -> Result<DocumentDownload, ServiceError> {
        let uc = DownloadDocumentUseCase {
            documents: self.document_repo.as_ref(),
            files: self.files_repo.as_ref(),
            storage: self.storage.as_ref(),
            access: self.access_repo.as_ref(),
            shares: self.share_access.as_ref(),
            snapshot: self.snapshot_service.as_ref(),
            exporter: self.exporter.as_ref(),
        };
        uc.download_workspace_root(actor, workspace_id, workspace_name, format)
            .await
            .map_err(|err| {
                if err
                    .downcast_ref::<FolderDownloadUnsupportedFormat>()
                    .is_some()
                {
                    ServiceError::BadRequest("folder_archive_only")
                } else {
                    ServiceError::from(err)
                }
            })?
            .ok_or(ServiceError::NotFound)
    }
}
