impl GitWorkspaceService {
    async fn apply_state_to_workspace(
        &self,
        workspace_id: Uuid,
        state: &HashMap<String, FileSnapshot>,
        previous_index: &HashMap<String, String>,
    ) -> anyhow::Result<u32> {
        let mut changed: u32 = 0;
        // write/update files
        for (path, snapshot) in state.iter() {
            let rel = format!("{}/{}", workspace_id, path.trim_start_matches('/'));
            let abs = self.storage.absolute_from_relative(&rel);
            if let Some(parent) = abs.parent() {
                async_fs::create_dir_all(parent).await?;
            }
            let bytes = self.snapshot_bytes(snapshot).await?;
            self.storage.write_bytes(abs.as_path(), &bytes).await?;
            changed += 1;
        }
        // remove files missing in next state
        for path in previous_index.keys() {
            if state.contains_key(path) {
                continue;
            }
            let rel = format!("{}/{}", workspace_id, path.trim_start_matches('/'));
            let abs = self.storage.absolute_from_relative(&rel);
            if async_fs::remove_file(&abs).await.is_ok() {
                changed += 1;
            }
        }
        Ok(changed)
    }

    async fn ensure_folder(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        folder_path: &str,
        cache: &mut HashMap<String, Uuid>,
    ) -> anyhow::Result<Option<Uuid>> {
        let trimmed = folder_path.trim_matches('/');
        if trimmed.is_empty() {
            return Ok(None);
        }

        let mut current_parent: Option<Uuid> = None;
        let mut accumulated = String::new();
        for segment in trimmed.split('/') {
            if !accumulated.is_empty() {
                accumulated.push('/');
            }
            accumulated.push_str(segment);

            if let Some(id) = cache.get(&accumulated) {
                current_parent = Some(*id);
                continue;
            }

            let lookup_path = format!("{}/{}", workspace_id, accumulated);
            if let Some(existing) = self
                .doc_paths
                .get_by_owner_and_path(workspace_id, &lookup_path)
                .await?
            {
                if existing.doc_type != DocumentType::Folder {
                    anyhow::bail!("path_conflict_not_folder");
                }
                cache.insert(accumulated.clone(), existing.id);
                current_parent = Some(existing.id);
                continue;
            }

            let title = if segment.trim().is_empty() {
                "folder"
            } else {
                segment
            };
            let parent_desired_path = match current_parent {
                Some(parent_id) => self
                    .docs
                    .get_meta_for_owner(parent_id, workspace_id)
                    .await?
                    .map(|m| m.desired_path),
                None => None,
            };
            let title = Title::from_user_input(title);
            let mut repo = self.docs.as_ref();
            let folder = application::documents::use_cases::create_document::CreateDocument {
                repo: &mut repo,
            }
            .execute(
                workspace_id,
                actor_id,
                &title,
                current_parent,
                parent_desired_path.as_ref(),
                DocumentType::Folder,
                None,
            )
            .await?;
            self.doc_paths
                .update_repo_path(folder.id, workspace_id, &accumulated)
                .await?;

            cache.insert(accumulated.clone(), folder.id);
            current_parent = Some(folder.id);
        }

        Ok(current_parent)
    }

    async fn materialize_documents_from_state(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        state: &HashMap<String, FileSnapshot>,
    ) -> anyhow::Result<(u32, u32)> {
        fn folder_key(path: &str) -> String {
            path.rsplitn(2, '/')
                .nth(1)
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(String::new)
        }

        fn attachment_owner_folder(path: &str) -> String {
            if let Some(idx) = path.find("/attachments/") {
                let prefix = &path[..idx];
                if prefix.is_empty() {
                    String::new()
                } else {
                    prefix.trim_end_matches('/').to_string()
                }
            } else if path.starts_with("attachments/") {
                String::new()
            } else {
                folder_key(path)
            }
        }

        fn is_markdown_path(path: &str) -> bool {
            let lower = path.to_ascii_lowercase();
            lower.ends_with(".md") || lower.ends_with(".markdown")
        }

        let mut folder_cache: HashMap<String, Uuid> = HashMap::new();
        let mut docs_created: u32 = 0;
        let mut attachments_created: u32 = 0;

        let mut existing_by_desired: HashMap<String, Uuid> = HashMap::new();
        let mut folder_docs: HashMap<String, Vec<Uuid>> = HashMap::new();

        for doc in self.docs.list_workspace_documents(workspace_id).await? {
            let normalized = normalize_repo_path(doc.desired_path.as_str().to_string());
            existing_by_desired.insert(normalized.clone(), doc.id);
            if doc.doc_type != DocumentType::Folder {
                let key = folder_key(&normalized);
                folder_docs.entry(key.clone()).or_default().push(doc.id);
                if doc.archived_at.is_some() {
                    let archived_key = if key.is_empty() {
                        "Archives".to_string()
                    } else {
                        format!("Archives/{}", key)
                    };
                    folder_docs.entry(archived_key).or_default().push(doc.id);
                }
            }
        }

        let mut paths: Vec<String> = state.keys().cloned().collect();
        paths.sort();

        // First pass: create documents only for markdown files
        for path in paths.iter() {
            let snapshot = match state.get(path) {
                Some(s) => s,
                None => continue,
            };
            if !snapshot.is_text {
                continue;
            }
            let normalized = normalize_repo_path(path.clone());
            if !is_markdown_path(&normalized) {
                continue;
            }

            // Skip if document already exists at desired_path (including folders that would conflict)
            if existing_by_desired.contains_key(&normalized) {
                continue;
            }

            let parent_path = folder_key(&normalized);
            let parent_id = if parent_path.is_empty() {
                None
            } else {
                self.ensure_folder(workspace_id, actor_id, &parent_path, &mut folder_cache)
                    .await?
            };

            let filename = normalized
                .rsplit('/')
                .next()
                .unwrap_or(&normalized)
                .to_string();
            let title = filename
                .trim_end_matches(".md")
                .trim_end_matches(".markdown")
                .trim_end_matches(".txt");

            let parent_desired_path = match parent_id {
                Some(parent_id) => self
                    .docs
                    .get_meta_for_owner(parent_id, workspace_id)
                    .await?
                    .map(|m| m.desired_path),
                None => None,
            };
            let title = Title::from_user_input(if title.is_empty() { "Document" } else { title });
            let mut repo = self.docs.as_ref();
            let doc = application::documents::use_cases::create_document::CreateDocument {
                repo: &mut repo,
            }
            .execute(
                workspace_id,
                actor_id,
                &title,
                parent_id,
                parent_desired_path.as_ref(),
                DocumentType::Document,
                None,
            )
            .await?;
            self.doc_paths
                .update_repo_path(doc.id, workspace_id, &normalized)
                .await?;
            docs_created += 1;
            existing_by_desired.insert(normalized.clone(), doc.id);

            folder_docs.entry(parent_path).or_default().push(doc.id);

            let bytes = self.snapshot_bytes(snapshot).await.unwrap_or_default();
            let body = extract_markdown_body(&bytes)
                .unwrap_or_else(|| std::str::from_utf8(&bytes).unwrap_or_default().to_string());
            let snap_bytes = snapshot_from_markdown(&body);
            let _ = self
                .realtime
                .apply_snapshot(&doc.id.to_string(), snap_bytes.as_slice())
                .await;
            let _ = self.realtime.force_persist(&doc.id.to_string()).await;
        }

        for docs in folder_docs.values_mut() {
            docs.sort();
        }

        // Second pass: attach binaries without creating documents
        for path in paths {
            let snapshot = match state.get(&path) {
                Some(s) => s,
                None => continue,
            };
            if snapshot.is_text {
                continue;
            }
            let normalized = normalize_repo_path(path.clone());
            if !normalized.contains("/attachments/") && !normalized.starts_with("attachments/") {
                continue;
            }
            let filename = normalized
                .rsplit('/')
                .next()
                .unwrap_or(&normalized)
                .to_string();
            let folder = attachment_owner_folder(&normalized);
            let doc_id = folder_docs.get(&folder).and_then(|v| v.first().copied());
            let Some(doc_id) = doc_id else {
                warn!(
                    workspace_id = %workspace_id,
                    repo_path = normalized.as_str(),
                    "git_materialize_attachment_no_owner"
                );
                continue;
            };

            let storage_path = format!("{}/{}", workspace_id, normalized);
            let existing: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM files WHERE storage_path = $1 LIMIT 1")
                    .bind(&storage_path)
                    .fetch_optional(&self.pool)
                    .await?;
            if existing.is_some() {
                continue;
            }

            let bytes = self.snapshot_bytes(snapshot).await.unwrap_or_default();
            let size = bytes.len() as i64;
            let _ = sqlx::query(
                r#"INSERT INTO files (document_id, filename, content_type, size, storage_path, content_hash)
                       VALUES ($1,$2,$3,$4,$5,$6)"#,
            )
            .bind(doc_id)
            .bind(&filename)
            .bind::<Option<&str>>(None)
            .bind(size)
            .bind(&storage_path)
            .bind(&snapshot.hash)
            .execute(&self.pool)
            .await?;
            attachments_created += 1;
        }
        Ok((docs_created, attachments_created))
    }

    /// Apply merged markdown files directly to realtime/persistence so documents reflect Pull results.
    async fn apply_merged_to_documents(
        &self,
        workspace_id: Uuid,
        next_state: &HashMap<String, FileSnapshot>,
    ) -> anyhow::Result<()> {
        let doc_rows = self
            .docs
            .list_workspace_documents(workspace_id)
            .await?
            .into_iter()
            .filter(|d| d.doc_type != DocumentType::Folder);

        for doc in doc_rows {
            let doc_id = doc.id;
            let normalized = normalize_repo_path(doc.desired_path.as_str().to_string());
            let Some(snapshot) = next_state.get(&normalized) else {
                continue;
            };

            if !snapshot.is_text {
                continue;
            }
            let bytes = match self.snapshot_bytes(snapshot).await {
                Ok(b) => b,
                Err(err) => {
                    warn!(document_id = %doc_id, error = ?err, "git_pull_snapshot_bytes_failed");
                    continue;
                }
            };
            let body = match extract_markdown_body(&bytes) {
                Some(b) => b,
                None => continue,
            };
            let snap_bytes =
                application::documents::services::realtime::snapshot::snapshot_from_markdown(&body);
            if let Err(err) = crate::core::storage::suppress_git_dirty(async {
                self.realtime
                    .apply_snapshot(&doc_id.to_string(), snap_bytes.as_slice())
                    .await?;
                self.realtime.force_persist(&doc_id.to_string()).await
            })
            .await
            {
                warn!(document_id = %doc_id, error = ?err, "git_pull_apply_snapshot_failed");
                continue;
            }
        }
        Ok(())
    }
}
