impl GitWorkspaceService {
    async fn collect_current_state(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<HashMap<String, FileSnapshot>> {
        let mut state: HashMap<String, FileSnapshot> = HashMap::new();

        let doc_rows = self
            .docs
            .list_workspace_documents(workspace_id)
            .await?
            .into_iter()
            .filter(|d| d.doc_type() != DocumentType::Folder);

        for doc in doc_rows {
            let doc_id = doc.id();
            let export = match self.snapshot.export_current_markdown(&doc_id).await? {
                Some(export) => export,
                None => continue,
            };
            let repo_path = export
                .repo_path
                .or_else(|| Some(doc.desired_path().as_str().to_string()))
                .map(normalize_repo_path)
                .ok_or_else(|| anyhow!("missing_repo_path_for_doc {}", doc_id))?;
            state.insert(
                repo_path,
                FileSnapshot {
                    hash: export.content_hash,
                    data: FileSnapshotData::Inline(export.bytes),
                    is_text: true,
                },
            );
        }

        let attachment_rows = sqlx::query(
            r#"SELECT f.id AS file_id, f.storage_path, f.content_hash
               FROM files f
               JOIN documents d ON d.id = f.document_id
               WHERE d.owner_id = $1"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        for row in attachment_rows {
            let file_id: Uuid = row.get("file_id");
            let storage_path: String = row.get("storage_path");
            let stored_hash: Option<String> = row
                .try_get("content_hash")
                .ok()
                .and_then(|h: String| if h.is_empty() { None } else { Some(h) });
            let (hash, needs_persist) = match stored_hash {
                Some(existing) => (existing, false),
                None => {
                    let computed = self
                        .compute_attachment_hash(&storage_path)
                        .await
                        .with_context(|| {
                            format!("failed to compute attachment hash for {}", storage_path)
                        })?;
                    match computed {
                        Some(value) => (value, true),
                        None => continue,
                    }
                }
            };
            if needs_persist {
                if let Err(err) = self.persist_attachment_hash(file_id, &hash).await {
                    warn!(
                        file_id = %file_id,
                        path = storage_path.as_str(),
                        error = ?err,
                        "git_workspace_attachment_hash_persist_failed"
                    );
                }
            }
            let repo_path = repo_relative_path(&storage_path)?;
            state.insert(
                repo_path,
                FileSnapshot {
                    hash,
                    data: FileSnapshotData::StoragePath(storage_path),
                    is_text: false,
                },
            );
        }

        Ok(state)
    }

    async fn compute_attachment_hash(&self, storage_path: &str) -> anyhow::Result<Option<String>> {
        let abs = self.storage.absolute_from_relative(storage_path);
        match self.storage.read_bytes(abs.as_path()).await {
            Ok(bytes) => Ok(Some(sha256_hex(&bytes))),
            Err(err) => {
                if let Some(io_err) = err.downcast_ref::<io::Error>() {
                    if io_err.kind() == io::ErrorKind::NotFound {
                        return Ok(None);
                    }
                }
                if err.to_string().to_lowercase().contains("not found") {
                    return Ok(None);
                }
                Err(err)
            }
        }
    }

    async fn persist_attachment_hash(&self, file_id: Uuid, hash: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"UPDATE files SET content_hash = $2, updated_at = now()
               WHERE id = $1"#,
        )
        .bind(file_id)
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
