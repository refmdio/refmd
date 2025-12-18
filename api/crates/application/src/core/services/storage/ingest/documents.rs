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
        if event.backend.is_fs_watcher()
            && event.actor_id.is_none()
            && self.recent_exports.is_recent_match(
                event.workspace_id,
                repo_path,
                &payload.content_hash,
            )
        {
            debug!(
                doc_id = %doc.id,
                repo_path = repo_path,
                "storage_ingest_doc_upsert_skipped_recent_projection"
            );
            return Ok(());
        }
        let snapshot = snapshot_from_markdown(&payload.body);
        self.realtime
            .apply_snapshot(&doc.id.to_string(), snapshot.as_slice())
            .await?;
        // Persist back to storage only for API/actor initiated ingests; fs_watcher/reconcile events
        // originate from the filesystem itself and writing would re-trigger the watcher endlessly.
        if event.actor_id.is_some() {
            if let Err(err) = self.realtime.force_persist(&doc.id.to_string()).await {
                warn!(
                    error = ?err,
                    doc_id = %doc.id,
                    "storage_ingest_force_persist_failed"
                );
            }
        }
        let mut payload_obj = serde_json::Map::new();
        payload_obj.insert("repo_path".into(), json!(repo_path));
        payload_obj.insert("backend".into(), json!(event.backend.as_str()));
        payload_obj.insert("content_hash".into(), json!(payload.content_hash));
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

    pub(super) async fn resolve_doc_from_front_matter(
        &self,
        user_id: Uuid,
        payload: &MarkdownIngestPayload,
    ) -> anyhow::Result<Option<ResolvedDocument>> {
        let Some(doc_id) = payload.doc_id_hint else {
            return Ok(None);
        };
        let Some(meta) = self
            .document_repo
            .get_meta_for_owner(doc_id, user_id)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(ResolvedDocument::new(
            doc_id,
            meta.doc_type,
            meta.path,
            meta.archived_at.is_some(),
        )))
    }

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
            .delete_for_user(event.workspace_id, doc.id, actor_id, &permissions)
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
            .document_repo
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
