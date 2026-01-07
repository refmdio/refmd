use super::*;

impl StorageIngestService {
    pub(super) async fn handle_doc_upsert(
        &self,
        doc: &ResolvedDocument,
        repo_path: &str,
        event: &StorageIngestEvent,
        payload: MarkdownIngestPayload,
        previous_repo_path: Option<&str>,
    ) -> anyhow::Result<()> {
        // E2EE: Skip recent export check using encrypted_hash
        if event.backend.is_fs_watcher()
            && event.actor_id.is_none()
            && self.recent_exports.is_recent_match(
                event.workspace_id,
                repo_path,
                &payload.encrypted_hash,
            )
        {
            debug!(
                doc_id = %doc.id,
                repo_path = repo_path,
                "storage_ingest_doc_upsert_skipped_recent_projection"
            );
            return Ok(());
        }

        // E2EE: No Yjs snapshot conversion - encrypted data is handled by client via WebSocket
        // Server only stores encrypted bytes as-is

        let mut payload_obj = serde_json::Map::new();
        payload_obj.insert("repo_path".into(), json!(repo_path));
        payload_obj.insert("backend".into(), json!(event.backend.as_str()));
        payload_obj.insert("encrypted_hash".into(), json!(payload.encrypted_hash));
        payload_obj.insert("size".into(), json!(payload.size));
        payload_obj.insert("doc_type".into(), json!(doc.doc_type.as_str()));
        if let Some(prev) = previous_repo_path {
            payload_obj.insert("previous_path".into(), json!(prev));
        }
        self.events
            .append(
                event.workspace_id,
                doc.id,
                "document.ingest_upsert",
                Some(Value::Object(payload_obj)),
            )
            .await?;
        info!(
            doc_id = %doc.id,
            repo_path = repo_path,
            backend = event.backend.as_str(),
            "storage_ingest_doc_upsert_applied"
        );
        Ok(())
    }

    pub(super) async fn load_markdown_payload(
        &self,
        rel_path: &str,
    ) -> anyhow::Result<MarkdownIngestPayload> {
        let abs = self.storage.absolute_from_relative(rel_path);
        let bytes = self.storage.read_bytes(abs.as_path()).await?;
        parse_markdown_payload(bytes)
    }

    // E2EE: resolve_doc_from_front_matter removed - document ID resolved from storage path

    pub(super) async fn handle_doc_delete(
        &self,
        doc: &ResolvedDocument,
        repo_path: &str,
        event: &StorageIngestEvent,
        permissions: &PermissionSet,
    ) -> anyhow::Result<()> {
        let actor_id = event.actor_id;
        match self
            .document_service
            .delete_for_user(event.workspace_id, doc.id, actor_id, permissions)
            .await
        {
            Ok(true) => {
                info!(
                    doc_id = %doc.id,
                    repo_path = repo_path,
                    backend = event.backend.as_str(),
                    "storage_ingest_doc_delete_applied"
                );
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(ServiceError::NotFound) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    pub(super) async fn handle_folder_upsert(
        &self,
        doc: &ResolvedDocument,
        rel_path: &str,
        repo_path: &str,
        event: &StorageIngestEvent,
        previous_repo_path: Option<&str>,
    ) -> anyhow::Result<()> {
        if !self
            .reconcile_repo_path(doc, event.workspace_id, rel_path)
            .await?
        {
            warn!(
                doc_id = %doc.id,
                repo_path = repo_path,
                "storage_ingest_folder_repo_path_rejected"
            );
            return Ok(());
        }
        let mut payload_obj = serde_json::Map::new();
        payload_obj.insert("repo_path".into(), json!(repo_path));
        payload_obj.insert("doc_type".into(), json!(doc.doc_type.as_str()));
        payload_obj.insert("owner_id".into(), json!(event.workspace_id));
        payload_obj.insert("backend".into(), json!(event.backend.as_str()));
        if let Some(prev) = previous_repo_path {
            payload_obj.insert("previous_path".into(), json!(prev));
        }
        self.events
            .append(
                event.workspace_id,
                doc.id,
                "document.metadata_updated",
                Some(Value::Object(payload_obj)),
            )
            .await?;
        info!(
            doc_id = %doc.id,
            repo_path = repo_path,
            backend = event.backend.as_str(),
            "storage_ingest_folder_upsert_applied"
        );
        Ok(())
    }

    pub(super) async fn reconcile_repo_path(
        &self,
        doc: &ResolvedDocument,
        owner_id: Uuid,
        rel_path: &str,
    ) -> anyhow::Result<bool> {
        if doc.path.as_deref() == Some(rel_path) {
            return Ok(true);
        }
        match self
            .document_paths
            .update_repo_path(doc.id, owner_id, rel_path)
            .await
        {
            Ok(()) => Ok(true),
            Err(err) => {
                warn!(
                    doc_id = %doc.id,
                    error = ?err,
                    "storage_ingest_repo_path_update_failed"
                );
                Ok(false)
            }
        }
    }
}
