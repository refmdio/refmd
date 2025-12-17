use super::*;

impl DocumentService {
    pub(super) async fn build_delete_plan(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        workspace_id: Uuid,
        root_meta: DocMeta,
    ) -> Result<Vec<delete_plan::DeleteEntry>, ServiceError> {
        let subtree = self
            .document_repo
            .list_owned_subtree_documents_tx(tx, workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)?;

        let mut nodes = Vec::new();
        for node in subtree {
            let meta = if node.id == doc_id {
                root_meta.clone()
            } else {
                self.document_repo
                    .get_meta_for_owner_tx(tx, node.id, workspace_id)
                    .await
                    .map_err(ServiceError::from)?
                    .ok_or(ServiceError::NotFound)?
            };
            let attachments = if node.doc_type != "folder" {
                self.files_repo
                    .list_storage_paths_for_document_tx(tx, node.id)
                    .await
                    .map_err(ServiceError::from)?
            } else {
                Vec::new()
            };
            nodes.push(delete_plan::DeleteNode {
                id: node.id,
                doc_type: node.doc_type,
                meta,
                attachments,
            });
        }

        let entries = delete_plan::build_delete_plan(doc_id, root_meta, nodes).map_err(|err| {
            error!(error = ?err, "build_delete_entries_failed");
            ServiceError::Unexpected(err.into())
        })?;
        Ok(entries)
    }

    pub(super) async fn enqueue_delete_job_for_entry(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        entry: &delete_plan::DeleteEntry,
        permission_snapshot: &[String],
        actor_id: Option<Uuid>,
    ) -> Result<(), ServiceError> {
        let repo_path = doc_path::workspace_repo_relative(workspace_id, entry.meta.path.as_deref())
            .unwrap_or_else(|| entry.meta.desired_path.clone());
        let metadata = StorageDeleteJobMetadata {
            workspace_id,
            repo_path: Some(repo_path),
            doc_type: entry.doc_type.clone(),
            attachment_paths: if entry.attachments.is_empty() {
                None
            } else {
                Some(entry.attachments.clone())
            },
            permission_snapshot: permission_snapshot.to_vec(),
            actor_id,
        };
        if entry.doc_type == "folder" {
            self.enqueue_folder_delete_tx(
                tx,
                workspace_id,
                entry.doc_id,
                entry.reason,
                Some(metadata),
            )
            .await
        } else {
            self.enqueue_doc_delete_tx(tx, workspace_id, entry.doc_id, entry.reason, Some(metadata))
                .await
        }
    }

    pub(super) async fn record_delete_event(
        &self,
        workspace_id: Uuid,
        entry: &delete_plan::DeleteEntry,
        actor_id: Option<Uuid>,
    ) {
        let repo_path = doc_path::workspace_repo_relative(workspace_id, entry.meta.path.as_deref())
            .unwrap_or_else(|| entry.meta.desired_path.clone());
        let previous_repo_path =
            doc_path::workspace_repo_relative(workspace_id, entry.meta.path.as_deref());
        let mut payload = json!({
            "doc_type": entry.doc_type,
            "repo_path": repo_path,
            "slug": entry.meta.slug,
            "desired_path": entry.meta.desired_path,
            "owner_id": workspace_id,
            "previous_path": previous_repo_path,
        });
        if let Some(actor) = actor_id {
            if let serde_json::Value::Object(ref mut map) = payload {
                map.insert("actor_id".into(), json!(actor));
            }
        }
        self.record_event(
            workspace_id,
            entry.doc_id,
            "document.deleted",
            Some(payload),
        )
        .await;
    }
}

