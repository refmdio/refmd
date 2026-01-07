use super::*;

#[async_trait]
impl StorageIngestHandler for StorageIngestService {
    async fn handle_event(&self, event: &StorageIngestEvent) -> anyhow::Result<()> {
        let Some(repo_path) = normalize_repo_path(&event.repo_path) else {
            warn!(
                user_id = %event.workspace_id,
                repo_path = event.repo_path.as_str(),
                "storage_ingest_invalid_repo_path"
            );
            return Ok(());
        };
        let rel_path = Self::relative_path(event.workspace_id, &repo_path);
        let payload_previous_repo_path = previous_path_from_payload(event.payload.as_ref());

        let mut doc_previous_repo_path: Option<String> = None;
        let mut doc = self
            .document_paths
            .get_by_owner_and_path(event.workspace_id, &rel_path)
            .await?
            .map(ResolvedDocument::from);

        if doc.is_none()
            && let Some(prev_repo) = payload_previous_repo_path.as_deref()
        {
            let prev_rel = Self::relative_path(event.workspace_id, prev_repo);
            if let Some(prev_doc) = self
                .document_paths
                .get_by_owner_and_path(event.workspace_id, &prev_rel)
                .await?
                .map(ResolvedDocument::from)
            {
                if let Err(err) = self
                    .document_paths
                    .update_repo_path(prev_doc.id, event.workspace_id, &rel_path)
                    .await
                {
                    warn!(
                        doc_id = %prev_doc.id,
                        error = ?err,
                        "storage_ingest_repo_path_update_failed"
                    );
                } else {
                    doc_previous_repo_path = Some(prev_repo.to_string());
                    let mut updated = prev_doc.clone();
                    updated.path = Some(rel_path.clone());
                    doc = Some(updated);
                }
            }
        }

        if let Some(doc) = doc {
            if doc.is_archived() {
                warn!(
                    doc_id = %doc.id,
                    repo_path = repo_path,
                    "storage_ingest_archived_doc_skipped"
                );
                return Ok(());
            }
            match event.kind {
                StorageIngestKind::Upsert => {
                    if doc.is_folder() {
                        self.handle_folder_upsert(
                            &doc,
                            &rel_path,
                            &repo_path,
                            event,
                            doc_previous_repo_path.as_deref(),
                        )
                        .await?;
                    } else {
                        let payload = match self.load_markdown_payload(&rel_path).await {
                            Ok(payload) => payload,
                            Err(err) if is_not_found_error(&err) => {
                                warn!(
                                    doc_id = %doc.id,
                                    repo_path = repo_path,
                                    "storage_ingest_doc_payload_missing"
                                );
                                self.storage_projection
                                    .delete_relative_path(&rel_path)
                                    .await?;
                                return Ok(());
                            }
                            Err(err) => return Err(err),
                        };
                        self.handle_doc_upsert(
                            &doc,
                            &repo_path,
                            event,
                            payload,
                            doc_previous_repo_path.as_deref(),
                        )
                        .await?;
                    }
                }
                StorageIngestKind::Delete => {
                    let permissions = self.permissions_for_event(event).await?;
                    self.handle_doc_delete(&doc, &repo_path, event, &permissions)
                        .await?;
                }
            }
            return Ok(());
        }

        let mut attachment_previous_repo_path: Option<String> = None;
        let mut attachment = self.files_repo.find_by_storage_path(&rel_path).await?;

        if attachment.is_none()
            && let Some(prev_repo) = payload_previous_repo_path.as_deref()
        {
            let prev_rel = Self::relative_path(event.workspace_id, prev_repo);
            if let Some(file) = self.files_repo.find_by_storage_path(&prev_rel).await? {
                self.files_repo
                    .update_storage_path(file.file_id, &rel_path)
                    .await?;
                attachment_previous_repo_path = Some(prev_repo.to_string());
                attachment = Some(file);
            }
        }

        if let Some(file) = attachment {
            info!(
                doc_id = %file.document_id,
                owner_id = %file.workspace_id,
                repo_path = repo_path,
                "storage_ingest_attachment_detected"
            );
            match event.kind {
                StorageIngestKind::Upsert => {
                    self.handle_attachment_upsert(
                        file.file_id,
                        file.document_id,
                        &rel_path,
                        &repo_path,
                        event,
                        attachment_previous_repo_path.as_deref(),
                    )
                    .await?;
                }
                StorageIngestKind::Delete => {
                    self.handle_attachment_delete(
                        file.file_id,
                        file.document_id,
                        &repo_path,
                        event,
                    )
                    .await?;
                }
            }
            return Ok(());
        }

        // E2EE: No front-matter resolution - document ID must be resolved from storage path
        // New documents are created via API, not from storage ingest
        if event.kind == StorageIngestKind::Upsert && rel_path.ends_with(".md") {
            info!(
                user_id = %event.workspace_id,
                repo_path = repo_path,
                "storage_ingest_orphan_encrypted_file"
            );
        }

        if event.kind == StorageIngestKind::Delete {
            self.storage_projection
                .delete_relative_path(&rel_path)
                .await?;
            info!(
                user_id = %event.workspace_id,
                repo_path = repo_path,
                backend = event.backend.as_str(),
                "storage_ingest_orphan_deleted"
            );
        } else {
            warn!(
                user_id = %event.workspace_id,
                repo_path = repo_path,
                backend = event.backend.as_str(),
                "storage_ingest_no_target_found"
            );
        }
        Ok(())
    }
}
