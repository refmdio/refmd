use domain::documents::doc_type::DocumentType;
use domain::documents::title::Title;

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
            .filter(|d| d.doc_type != DocumentType::Folder);

        for doc in doc_rows {
            let export = match self.snapshot.export_current_markdown(&doc.id).await? {
                Some(export) => export,
                None => continue,
            };
            let repo_path = export
                .repo_path
                .or_else(|| Some(doc.desired_path.as_str().to_string()))
                .map(normalize_repo_path)
                .ok_or_else(|| anyhow!("missing_repo_path_for_doc {}", doc.id))?;
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

impl GitWorkspaceService {
    async fn fetch_dirty(&self, workspace_id: Uuid) -> anyhow::Result<Vec<DirtyRow>> {
        let rows = sqlx::query(
            r#"SELECT path, is_text, op, content_hash
               FROM git_dirty_files
               WHERE workspace_id = $1
               ORDER BY created_at ASC"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let path: String = r.get("path");
            let is_text: bool = r.get("is_text");
            let op: String = r.get("op");
            let content_hash: Option<String> = r.try_get("content_hash").ok();
            out.push(DirtyRow {
                path,
                is_text,
                op,
                content_hash,
            });
        }
        Ok(out)
    }

    async fn clear_dirty(&self, workspace_id: Uuid) -> anyhow::Result<u64> {
        let res = sqlx::query("DELETE FROM git_dirty_files WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }
}

impl GitWorkspaceService {
    async fn export_markdown_for_repo_path(
        &self,
        workspace_id: Uuid,
        repo_path: &str,
    ) -> anyhow::Result<Option<(Vec<u8>, String)>> {
        let trimmed = repo_path.trim_start_matches('/');
        let mut candidates: Vec<(&str, bool)> = vec![(trimmed, false)];
        if let Some(stripped) = trimmed.strip_prefix("Archives/") {
            if !stripped.is_empty() {
                candidates.push((stripped, true));
            }
        }

        // First try by normalized repo path (documents.path). Fall back to desired_path for older records.
        let all_docs = self.docs.list_workspace_documents(workspace_id).await?;

        for (candidate, archived_only) in candidates {
            let lookup_path = format!("{}/{}", workspace_id, candidate);
            let from_path = self
                .docs
                .get_by_owner_and_path(workspace_id, &lookup_path)
                .await?;

            let doc = if let Some(doc) = from_path {
                Some(doc)
            } else {
                all_docs
                    .iter()
                    .find(|d| normalize_repo_path(d.desired_path.as_str().to_string()) == candidate)
                    .cloned()
            };

            if let Some(doc) = doc {
                if doc.doc_type == DocumentType::Folder {
                    continue;
                }
                if archived_only && doc.archived_at.is_none() {
                    continue;
                }
                if let Some(export) = self.snapshot.export_current_markdown(&doc.id).await? {
                    return Ok(Some((export.bytes, export.content_hash)));
                }
            }
        }

        Ok(None)
    }
}

impl GitWorkspaceService {
    fn compute_deltas(
        &self,
        current: &HashMap<String, FileSnapshot>,
        previous: &HashMap<String, String>,
    ) -> FileDeltaSummary {
        let mut added = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();

        for (path, snapshot) in current.iter() {
            match previous.get(path) {
                None => added.push(path.clone()),
                Some(prev_hash) if prev_hash != &snapshot.hash => modified.push(path.clone()),
                _ => {}
            }
        }

        for path in previous.keys() {
            if !current.contains_key(path) {
                deleted.push(path.clone());
            }
        }

        FileDeltaSummary {
            added,
            modified,
            deleted,
        }
    }
}

impl GitWorkspaceService {
    async fn store_commit_snapshots(
        &self,
        workspace_id: Uuid,
        commit_id: &[u8],
        state: &HashMap<String, FileSnapshot>,
    ) -> anyhow::Result<Vec<BlobKey>> {
        let mut stored = Vec::new();
        for (path, snapshot) in state.iter() {
            let key = blob_key(workspace_id, commit_id, path);
            let bytes = self.snapshot_bytes(snapshot).await?;
            if let Err(err) = self.git_storage.put_blob(&key, &bytes).await {
                for key in stored.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                return Err(err);
            }
            stored.push(key);
        }
        Ok(stored)
    }

    async fn snapshot_bytes(&self, snapshot: &FileSnapshot) -> anyhow::Result<Vec<u8>> {
        match &snapshot.data {
            FileSnapshotData::Inline(bytes) => Ok(bytes.clone()),
            FileSnapshotData::StoragePath(path) => {
                let abs = self.storage.absolute_from_relative(path);
                self.storage.read_bytes(abs.as_path()).await
            }
        }
    }

    async fn load_file_snapshot(
        &self,
        workspace_id: Uuid,
        commit_id: &[u8],
        path: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let key = blob_key(workspace_id, commit_id, path);
        match self.git_storage.fetch_blob(&key).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) => {
                // Treat missing blob as absence (e.g., binary or not stored).
                if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::NotFound {
                        return Ok(None);
                    }
                }
                if err.to_string().contains("not found") {
                    return Ok(None);
                }
                Err(err)
            }
        }
    }

    #[allow(dead_code)]
    async fn state_from_commit_meta(
        &self,
        workspace_id: Uuid,
        meta: &CommitMeta,
    ) -> anyhow::Result<HashMap<String, FileSnapshot>> {
        let mut state: HashMap<String, FileSnapshot> = HashMap::new();
        for path in meta.file_hash_index.keys() {
            let Some(bytes) = self
                .load_file_snapshot(workspace_id, &meta.commit_id, path)
                .await?
            else {
                continue;
            };
            let hash = sha256_hex(&bytes);
            let is_text = std::str::from_utf8(&bytes).is_ok();
            state.insert(
                path.clone(),
                FileSnapshot {
                    hash,
                    data: FileSnapshotData::Inline(bytes),
                    is_text,
                },
            );
        }
        Ok(state)
    }
}

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
                .docs
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
            self.docs
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
            self.docs
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

impl GitWorkspaceService {
    fn build_diff_result(
        &self,
        path: &str,
        old_content: Option<&str>,
        new_content: Option<&str>,
    ) -> TextDiffResult {
        match (old_content, new_content) {
            (Some(old), Some(new)) => compute_text_diff(old, new, path),
            _ => TextDiffResult {
                file_path: path.to_string(),
                diff_lines: Vec::new(),
                old_content: old_content.map(|s| s.to_string()),
                new_content: new_content.map(|s| s.to_string()),
            },
        }
    }

    async fn commit_diff_via_packs(
        &self,
        workspace_id: Uuid,
        from_meta: Option<&CommitMeta>,
        to_meta: &CommitMeta,
    ) -> anyhow::Result<Vec<TextDiffResult>> {
        let (to_pack_dir, to_pack_paths) = self
            .persist_pack_chain(workspace_id, Some(to_meta.commit_id.as_slice()))
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "missing pack data for commit {}",
                    encode_commit_id(&to_meta.commit_id)
                )
            })?;

        let from_pack = if let Some(from_meta) = from_meta {
            if from_meta.commit_id != to_meta.commit_id {
                Some(
                    self.persist_pack_chain(workspace_id, Some(from_meta.commit_id.as_slice()))
                        .await?
                        .ok_or_else(|| {
                            anyhow!(
                                "missing pack data for commit {}",
                                encode_commit_id(&from_meta.commit_id)
                            )
                        })?,
                )
            } else {
                None
            }
        } else {
            None
        };

        let temp_dir = TempDirBuilder::new()
            .prefix("git-diff-")
            .tempdir()
            .map_err(|e| anyhow::anyhow!(e))?;
        let repo = Repository::init_bare(temp_dir.path())?;

        apply_pack_files(&repo, &to_pack_paths)?;
        if let Some((_, ref paths)) = from_pack {
            apply_pack_files(&repo, paths)?;
        }

        let from_files = if let Some(from_meta) = from_meta {
            read_commit_files(&repo, from_meta.commit_id.as_slice())?
        } else {
            HashMap::new()
        };
        let to_files = read_commit_files(&repo, to_meta.commit_id.as_slice())?;

        drop(repo);
        let _ = temp_dir.close();
        drop(to_pack_dir);
        if let Some((dir, _)) = from_pack {
            drop(dir);
        }

        let mut paths: BTreeSet<String> = BTreeSet::new();
        paths.extend(from_files.keys().cloned());
        paths.extend(to_files.keys().cloned());

        let mut results = Vec::new();
        for path in paths {
            let old_bytes = from_files.get(&path);
            let new_bytes = to_files.get(&path);
            let old_content = old_bytes
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(|s| s.to_string());
            let new_content = new_bytes
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(|s| s.to_string());
            if old_content.is_none() && new_content.is_none() {
                if old_bytes.is_some() || new_bytes.is_some() {
                    results.push(self.build_diff_result(&path, None, None));
                }
                continue;
            }
            results.push(self.build_diff_result(
                &path,
                old_content.as_deref(),
                new_content.as_deref(),
            ));
        }
        Ok(results)
    }

    async fn commit_diff_from_storage(
        &self,
        workspace_id: Uuid,
        from_meta: Option<&CommitMeta>,
        to_meta: Option<&CommitMeta>,
    ) -> anyhow::Result<Vec<TextDiffResult>> {
        let Some(to_meta) = to_meta else {
            return Ok(Vec::new());
        };

        let mut paths: BTreeSet<String> = BTreeSet::new();
        if let Some(meta) = from_meta {
            paths.extend(meta.file_hash_index.keys().cloned());
        }
        paths.extend(to_meta.file_hash_index.keys().cloned());

        let mut results = Vec::new();
        for path in paths {
            let old_hash = from_meta.and_then(|meta| meta.file_hash_index.get(&path));
            let new_hash = to_meta.file_hash_index.get(&path);
            if let (Some(old), Some(new)) = (old_hash, new_hash) {
                if old == new {
                    continue;
                }
            }

            let old_bytes = match (from_meta, old_hash) {
                (Some(meta), Some(_)) => {
                    self.load_file_snapshot(workspace_id, meta.commit_id.as_slice(), &path)
                        .await?
                }
                _ => None,
            };
            let new_bytes = match new_hash {
                Some(_) => {
                    self.load_file_snapshot(workspace_id, to_meta.commit_id.as_slice(), &path)
                        .await?
                }
                None => None,
            };

            let old_text = old_bytes
                .as_ref()
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(|s| s.to_string());
            let new_text = new_bytes
                .as_ref()
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(|s| s.to_string());

            if old_text.is_none() && new_text.is_none() {
                if old_bytes.is_some() || new_bytes.is_some() {
                    results.push(self.build_diff_result(&path, None, None));
                }
            } else {
                results.push(self.build_diff_result(
                    &path,
                    old_text.as_deref(),
                    new_text.as_deref(),
                ));
            }
        }

        Ok(results)
    }
}
