use serde_json::json;
use uuid::Uuid;

use domain::access::permissions::PermissionSet;
use domain::documents::doc_type::DocumentType;
use domain::documents::document::Document as DomainDocument;
use domain::documents::policy::DocumentState;
use domain::documents::{path as doc_path, policy as doc_policy};

use crate::core::services::errors::ServiceError;
use crate::documents::ports::tx_runner::run_in_tx;

use super::DocumentService;
use super::util::{map_policy_error, map_tx_error};

impl DocumentService {
    pub async fn archive_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<DomainDocument, ServiceError> {
        let meta = self.load_owner_meta(workspace_id, doc_id).await?;
        let state = DocumentState::new(meta.doc_type, meta.archived_at);
        doc_policy::ensure_archivable(state, permissions).map_err(map_policy_error)?;
        let previous_repo_path =
            doc_path::workspace_repo_relative(workspace_id, meta.path.as_deref())
                .map(|p| p.into_string());
        let subtree = self
            .document_repo
            .list_owned_subtree_documents(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)?;
        for node in &subtree {
            if node.doc_type != DocumentType::Folder {
                self.realtime.force_persist(&node.id.to_string()).await?;
            }
        }

        let doc = run_in_tx(self.tx_runner.as_ref(), move |tx| {
            Box::pin(async move {
                let doc = tx
                    .documents()
                    .archive_subtree(doc_id, workspace_id, actor_id)
                    .await?;
                let Some(doc) = doc else {
                    return Err(ServiceError::NotFound.into());
                };
                Self::enqueue_projection_for_document_tx(
                    tx.storage_jobs(),
                    &doc,
                    "archive_document",
                )
                .await?;
                Ok(doc)
            })
        })
        .await
        .map_err(map_tx_error)?;

        for node in &subtree {
            self.realtime
                .set_document_editable(&node.id.to_string(), false)
                .await?;
        }
        let repo_path = doc.desired_path.as_str().to_string();
        let event_payload = json!({
            "repo_path": repo_path,
            "doc_type": doc.doc_type.as_str(),
            "slug": doc.slug.as_str(),
            "desired_path": doc.desired_path.as_str(),
            "owner_id": doc.workspace_id,
            "actor_id": actor_id,
            "previous_path": previous_repo_path,
            "previous_desired_path": meta.desired_path.as_str(),
        });
        self.record_event(
            doc.workspace_id,
            doc.id,
            "document.archived",
            Some(event_payload),
        )
        .await;
        Ok(doc)
    }

    pub async fn unarchive_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<DomainDocument, ServiceError> {
        let meta = self.load_owner_meta(workspace_id, doc_id).await?;
        let state = DocumentState::new(meta.doc_type, meta.archived_at);
        doc_policy::ensure_unarchivable(state, permissions).map_err(map_policy_error)?;
        let previous_repo_path =
            doc_path::workspace_repo_relative(workspace_id, meta.path.as_deref())
                .map(|p| p.into_string());
        let subtree = self
            .document_repo
            .list_owned_subtree_documents(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)?;

        let doc = run_in_tx(self.tx_runner.as_ref(), move |tx| {
            Box::pin(async move {
                let doc = tx
                    .documents()
                    .unarchive_subtree(doc_id, workspace_id)
                    .await?;
                let Some(doc) = doc else {
                    return Err(ServiceError::NotFound.into());
                };
                Self::enqueue_projection_for_document_tx(
                    tx.storage_jobs(),
                    &doc,
                    "unarchive_document",
                )
                .await?;
                Ok(doc)
            })
        })
        .await
        .map_err(map_tx_error)?;

        for node in &subtree {
            self.realtime
                .set_document_editable(&node.id.to_string(), true)
                .await?;
        }
        for node in &subtree {
            if node.doc_type != DocumentType::Folder {
                self.realtime.force_persist(&node.id.to_string()).await?;
            }
        }
        let repo_path = doc.desired_path.as_str().to_string();
        let event_payload = json!({
            "repo_path": repo_path,
            "doc_type": doc.doc_type.as_str(),
            "slug": doc.slug.as_str(),
            "desired_path": doc.desired_path.as_str(),
            "owner_id": doc.workspace_id,
            "actor_id": actor_id,
            "previous_path": previous_repo_path,
            "previous_desired_path": meta.desired_path.as_str(),
        });
        self.record_event(
            doc.workspace_id,
            doc.id,
            "document.unarchived",
            Some(event_payload),
        )
        .await;
        Ok(doc)
    }
}
