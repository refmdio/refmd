use super::*;

impl DocumentService {
    pub(super) async fn enqueue_projection_for_document_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc: &DomainDocument,
        reason: &'static str,
    ) -> Result<(), ServiceError> {
        if doc.doc_type == "folder" {
            self.enqueue_folder_sync_tx(tx, doc.workspace_id, doc.id, reason)
                .await
        } else {
            self.enqueue_doc_sync_tx(tx, doc.workspace_id, doc.id, reason)
                .await
        }
    }

    pub(super) async fn enqueue_doc_sync_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        doc_id: Uuid,
        reason: &'static str,
    ) -> Result<(), ServiceError> {
        let encoded_reason = serde_json::to_string(&StorageJobReason {
            reason: reason.to_string(),
            metadata: Some(WorkspaceJobMetadata { workspace_id }),
        })
        .ok();
        self.storage_jobs
            .enqueue_doc_job_tx(
                tx,
                workspace_id,
                doc_id,
                StorageProjectionJobKind::DocSync,
                encoded_reason.as_deref(),
            )
            .await
            .map_err(|err| {
                warn!(
                    error = ?err,
                    doc_id = %doc_id,
                    "storage_projection_enqueue_failed"
                );
                ServiceError::Unexpected(err)
            })
    }

    pub(super) async fn enqueue_doc_delete_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        doc_id: Uuid,
        reason: &'static str,
        metadata: Option<StorageDeleteJobMetadata>,
    ) -> Result<(), ServiceError> {
        let encoded_reason = metadata.and_then(|meta| {
            serde_json::to_string(&StorageJobReason {
                reason: reason.to_string(),
                metadata: Some(meta),
            })
            .ok()
        });
        let reason_str = encoded_reason.as_deref().unwrap_or(reason);
        self.storage_jobs
            .enqueue_doc_job_tx(
                tx,
                workspace_id,
                doc_id,
                StorageProjectionJobKind::DeleteDoc,
                Some(reason_str),
            )
            .await
            .map_err(|err| {
                warn!(
                    error = ?err,
                    doc_id = %doc_id,
                    "storage_projection_enqueue_failed"
                );
                ServiceError::Unexpected(err)
            })
    }

    pub(super) async fn enqueue_folder_sync_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        folder_id: Uuid,
        reason: &'static str,
    ) -> Result<(), ServiceError> {
        self.storage_jobs
            .enqueue_folder_job_tx(
                tx,
                workspace_id,
                folder_id,
                StorageProjectionJobKind::FolderSync,
                Some(reason),
            )
            .await
            .map_err(|err| {
                warn!(
                    error = ?err,
                    folder_id = %folder_id,
                    "storage_projection_enqueue_failed"
                );
                ServiceError::Unexpected(err)
            })
    }

    pub(super) async fn enqueue_folder_delete_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        folder_id: Uuid,
        reason: &'static str,
        metadata: Option<StorageDeleteJobMetadata>,
    ) -> Result<(), ServiceError> {
        let encoded_reason = metadata.and_then(|meta| {
            serde_json::to_string(&StorageJobReason {
                reason: reason.to_string(),
                metadata: Some(meta),
            })
            .ok()
        });
        let reason_str = encoded_reason.as_deref().unwrap_or(reason);
        self.storage_jobs
            .enqueue_folder_job_tx(
                tx,
                workspace_id,
                folder_id,
                StorageProjectionJobKind::DeleteFolder,
                Some(reason_str),
            )
            .await
            .map_err(|err| {
                warn!(
                    error = ?err,
                    folder_id = %folder_id,
                    "storage_projection_enqueue_failed"
                );
                ServiceError::Unexpected(err)
            })
    }
}

