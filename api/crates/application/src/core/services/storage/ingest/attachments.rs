use super::*;

impl StorageIngestService {
    pub(super) async fn handle_attachment_upsert(
        &self,
        file_id: Uuid,
        doc_id: Uuid,
        rel_path: &str,
        repo_path: &str,
        event: &StorageIngestEvent,
        previous_repo_path: Option<&str>,
    ) -> anyhow::Result<()> {
        let abs = self.storage.absolute_from_relative(rel_path);
        let bytes = match self.storage.read_bytes(abs.as_path()).await {
            Ok(bytes) => bytes,
            Err(err) if is_not_found_error(&err) => {
                warn!(
                    file_id = %file_id,
                    doc_id = %doc_id,
                    repo_path = repo_path,
                    "storage_ingest_attachment_missing_skipped"
                );
                self.storage_projection
                    .delete_relative_path(rel_path)
                    .await?;
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };

        // E2EE: Validate RME1 format
        if bytes.len() < 4 || &bytes[0..4] != RME1_MAGIC {
            warn!(
                file_id = %file_id,
                doc_id = %doc_id,
                repo_path = repo_path,
                "storage_ingest_attachment_invalid_rme1_format"
            );
            return Ok(());
        }

        let size = bytes.len() as i64;
        let encrypted_hash = sha256_hex(&bytes);
        self.files_repo
            .update_hash_and_size(file_id, size, &encrypted_hash)
            .await?;
        let mut payload_obj = serde_json::Map::new();
        payload_obj.insert("repo_path".into(), json!(repo_path));
        payload_obj.insert("storage_path".into(), json!(rel_path));
        payload_obj.insert("backend".into(), json!(event.backend.as_str()));
        payload_obj.insert("size".into(), json!(size));
        payload_obj.insert("encrypted_hash".into(), json!(encrypted_hash));
        if let Some(prev) = previous_repo_path {
            payload_obj.insert("previous_path".into(), json!(prev));
        }
        self.events
            .append(
                event.workspace_id,
                doc_id,
                "attachment.ingest_upsert",
                Some(Value::Object(payload_obj)),
            )
            .await?;
        info!(
            doc_id = %doc_id,
            file_id = %file_id,
            repo_path = repo_path,
            backend = event.backend.as_str(),
            "storage_ingest_attachment_upsert_applied"
        );
        Ok(())
    }

    pub(super) async fn handle_attachment_delete(
        &self,
        file_id: Uuid,
        doc_id: Uuid,
        repo_path: &str,
        event: &StorageIngestEvent,
    ) -> anyhow::Result<()> {
        self.files_repo.delete_by_id(file_id).await?;
        self.events
            .append(
                event.workspace_id,
                doc_id,
                "attachment.ingest_delete",
                Some(json!({
                    "repo_path": repo_path,
                    "backend": event.backend.as_str(),
                })),
            )
            .await?;
        info!(
            doc_id = %doc_id,
            file_id = %file_id,
            repo_path = repo_path,
            backend = event.backend.as_str(),
            "storage_ingest_attachment_deleted"
        );
        Ok(())
    }
}
