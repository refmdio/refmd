use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use domain::documents::document::Document as DomainDocument;

use crate::core::services::access::{self, Actor};
use crate::core::services::errors::ServiceError;
use crate::documents::ports::tx_runner::run_in_tx;
use crate::documents::services::realtime::snapshot::snapshot_from_markdown;

use super::DocumentService;
use super::patch::{DocumentPatchOperation, apply_patch_operations};
use super::util::map_tx_error;

impl DocumentService {
    pub async fn get_content(&self, actor: &Actor, doc_id: Uuid) -> Result<String, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => ServiceError::NotFound,
            other => other,
        })?;

        let content = self
            .realtime
            .get_content(&doc_id.to_string())
            .await
            .map_err(ServiceError::from)?
            .unwrap_or_default();
        Ok(content)
    }

    pub async fn update_content(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        content: &str,
    ) -> Result<DomainDocument, ServiceError> {
        access::require_edit(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => ServiceError::Unauthorized,
            other => other,
        })?;

        let snapshot_bytes = snapshot_from_markdown(content);
        self.realtime
            .apply_snapshot(&doc_id.to_string(), snapshot_bytes.as_slice())
            .await
            .map_err(ServiceError::from)?;

        if let Err(err) = self.realtime.force_persist(&doc_id.to_string()).await {
            warn!(document_id = %doc_id, error = ?err, "document_force_persist_after_update_failed");
        }

        let doc = self
            .document_repo
            .get_by_id(doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        let workspace_id = doc.workspace_id;
        let doc_id = doc.id;
        run_in_tx(self.tx_runner.as_ref(), move |tx| {
            Box::pin(async move {
                Self::enqueue_doc_sync_tx(
                    tx.storage_jobs(),
                    workspace_id,
                    doc_id,
                    "update_content",
                )
                .await?;
                Ok(())
            })
        })
        .await
        .map_err(map_tx_error)?;
        let repo_path = doc.desired_path.as_str().to_string();
        let event_payload = json!({
            "repo_path": repo_path,
            "desired_path": doc.desired_path.as_str(),
            "slug": doc.slug.as_str(),
            "doc_type": doc.doc_type.as_str(),
            "owner_id": doc.workspace_id,
        });
        self.record_event(
            doc.workspace_id,
            doc.id,
            "document.content_updated",
            Some(event_payload),
        )
        .await;
        Ok(doc)
    }

    pub async fn patch_content(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        operations: &[DocumentPatchOperation],
    ) -> Result<DomainDocument, ServiceError> {
        if operations.is_empty() {
            return Err(ServiceError::BadRequest("patch_operations_required"));
        }

        access::require_edit(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|err| match err {
            ServiceError::Forbidden => ServiceError::Unauthorized,
            other => other,
        })?;

        let current = self
            .realtime
            .get_content(&doc_id.to_string())
            .await
            .map_err(ServiceError::from)?
            .unwrap_or_default();
        let updated = apply_patch_operations(&current, operations)?;

        self.update_content(actor, doc_id, &updated).await
    }
}
