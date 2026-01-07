use serde_json::json;
use tracing::warn;
use uuid::Uuid;

use domain::documents::document::Document as DomainDocument;

use crate::core::services::access::{self, Actor};
use crate::core::services::errors::ServiceError;
use crate::documents::dtos::ContentDto;
use crate::documents::ports::realtime::realtime_port::EncryptedUpdate;
use crate::documents::ports::tx_runner::run_in_tx;
use crate::documents::services::realtime::snapshot::snapshot_from_markdown;

use super::DocumentService;
use super::patch::{DocumentPatchOperation, apply_patch_operations};
use super::util::map_tx_error;

impl DocumentService {
    /// Get document content as Yjs snapshot bytes.
    /// Returns ContentDto with content bytes and optional nonce (for E2EE documents).
    pub async fn get_content(&self, actor: &Actor, doc_id: Uuid) -> Result<ContentDto, ServiceError> {
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

        let snapshot = self
            .realtime
            .get_snapshot(&doc_id.to_string())
            .await
            .map_err(ServiceError::from)?;

        match snapshot {
            Some(data) => Ok(ContentDto {
                content: data.data,
                nonce: data.nonce,
            }),
            None => Ok(ContentDto {
                content: Vec::new(),
                nonce: None,
            }),
        }
    }

    /// Update document content.
    /// - For plaintext mode: pass content bytes (Yjs state), nonce and signature as None
    /// - For E2EE mode: pass encrypted content bytes with nonce and optional signature
    pub async fn update_content(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        content: &[u8],
        nonce: Option<&[u8]>,
        signature: Option<&[u8]>,
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

        // Apply snapshot with optional E2EE metadata
        self.realtime
            .apply_encrypted_snapshot(&doc_id.to_string(), content, nonce, signature)
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
        let workspace_id = doc.workspace_id();
        let doc_id = doc.id();
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

        let is_encrypted = nonce.is_some();
        let repo_path = doc.desired_path().as_str().to_string();
        let event_payload = json!({
            "repo_path": repo_path,
            "desired_path": doc.desired_path().as_str(),
            "slug": doc.slug().as_str(),
            "doc_type": doc.doc_type().as_str(),
            "owner_id": doc.workspace_id(),
            "encrypted": is_encrypted,
        });
        self.record_event(
            doc.workspace_id(),
            doc.id(),
            "document.content_updated",
            Some(event_payload),
        )
        .await;
        Ok(doc)
    }

    /// Update document content from markdown string (convenience method for plaintext mode).
    pub async fn update_content_from_markdown(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        content: &str,
    ) -> Result<DomainDocument, ServiceError> {
        let snapshot_bytes = snapshot_from_markdown(content);
        self.update_content(actor, doc_id, &snapshot_bytes, None, None).await
    }

    /// Patch document content.
    /// - For plaintext mode: pass DocumentPatchOperation with text
    /// - For E2EE mode: pass EncryptedUpdate with encrypted data and nonce
    pub async fn patch_content(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        plaintext_operations: Option<&[DocumentPatchOperation]>,
        encrypted_updates: Option<&[EncryptedUpdate]>,
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

        let is_encrypted = encrypted_updates.is_some() && !encrypted_updates.unwrap().is_empty();

        if let Some(updates) = encrypted_updates {
            if !updates.is_empty() {
                // E2EE mode: apply encrypted updates
                self.realtime
                    .apply_encrypted_updates(&doc_id.to_string(), updates)
                    .await
                    .map_err(ServiceError::from)?;
            }
        } else if let Some(operations) = plaintext_operations {
            if operations.is_empty() {
                return Err(ServiceError::BadRequest("patch_operations_required"));
            }
            // Plaintext mode: get current content, apply operations, update
            let current = self
                .realtime
                .get_content(&doc_id.to_string())
                .await
                .map_err(ServiceError::from)?
                .unwrap_or_default();
            let updated = apply_patch_operations(&current, operations)?;
            let snapshot_bytes = snapshot_from_markdown(&updated);
            self.realtime
                .apply_snapshot(&doc_id.to_string(), &snapshot_bytes)
                .await
                .map_err(ServiceError::from)?;
        } else {
            return Err(ServiceError::BadRequest("patch_operations_required"));
        }

        if let Err(err) = self.realtime.force_persist(&doc_id.to_string()).await {
            warn!(document_id = %doc_id, error = ?err, "document_force_persist_after_patch_failed");
        }

        let doc = self
            .document_repo
            .get_by_id(doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        let workspace_id = doc.workspace_id();
        let doc_id = doc.id();
        run_in_tx(self.tx_runner.as_ref(), move |tx| {
            Box::pin(async move {
                Self::enqueue_doc_sync_tx(
                    tx.storage_jobs(),
                    workspace_id,
                    doc_id,
                    "patch_content",
                )
                .await?;
                Ok(())
            })
        })
        .await
        .map_err(map_tx_error)?;

        let repo_path = doc.desired_path().as_str().to_string();
        let event_payload = json!({
            "repo_path": repo_path,
            "desired_path": doc.desired_path().as_str(),
            "slug": doc.slug().as_str(),
            "doc_type": doc.doc_type().as_str(),
            "owner_id": doc.workspace_id(),
            "encrypted": is_encrypted,
        });
        self.record_event(
            doc.workspace_id(),
            doc.id(),
            "document.content_patched",
            Some(event_payload),
        )
        .await;

        Ok(doc)
    }
}
