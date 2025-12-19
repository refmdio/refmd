#[async_trait]
impl GitWorkspacePort for GitWorkspaceService {

    async fn ensure_repository(
        &self,
        workspace_id: Uuid,
        default_branch: &str,
    ) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            sqlx::query(
                r#"INSERT INTO git_repository_state (workspace_id, initialized, default_branch, initialized_at, updated_at)
               VALUES ($1, true, $2, now(), now())
               ON CONFLICT (workspace_id) DO UPDATE SET
                 initialized = true,
                 default_branch = EXCLUDED.default_branch,
                 initialized_at = COALESCE(git_repository_state.initialized_at, EXCLUDED.initialized_at),
                 updated_at = now()"#,
            )
            .bind(workspace_id)
            .bind(default_branch)
            .execute(&self.pool)
            .await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn remove_repository(&self, workspace_id: Uuid) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            let mut tx = self.pool.begin().await?;
            sqlx::query("DELETE FROM git_dirty_files WHERE workspace_id = $1")
                .bind(workspace_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM git_commits WHERE workspace_id = $1")
                .bind(workspace_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE git_repository_state SET initialized = false, updated_at = now() WHERE workspace_id = $1",
            )
            .bind(workspace_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            self.git_storage.delete_all(workspace_id).await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn status(&self, workspace_id: Uuid) -> PortResult<GitWorkspaceStatus> {
        let out: anyhow::Result<GitWorkspaceStatus> = async {
            let state = self.load_repository_state(workspace_id).await?;
            let Some((initialized, branch)) = state else {
                return Ok(GitWorkspaceStatus {
                    repository_initialized: false,
                    current_branch: None,
                    uncommitted_changes: 0,
                    untracked_files: 0,
                });
            };
            if !initialized {
                return Ok(GitWorkspaceStatus {
                    repository_initialized: false,
                    current_branch: Some(branch),
                    uncommitted_changes: 0,
                    untracked_files: 0,
                });
            }
            // Dirty-driven status: avoid full workspace scan
            let latest = self.latest_commit_meta(workspace_id).await?;
            let previous_index: HashMap<String, String> = latest
                .as_ref()
                .map(|c| c.file_hash_index.clone())
                .unwrap_or_default();

            let dirty = self.fetch_dirty(workspace_id).await?;
            let mut added: u32 = 0;
            let mut modified: u32 = 0;
            let mut deleted: u32 = 0;

            for d in dirty.iter() {
                match d.op.as_str() {
                    "upsert" => {
                        if let Some(prev_hash) = previous_index.get(&d.path) {
                            // Existing file: if hash unchanged and hash known, ignore; else modified
                            match d.content_hash.as_ref() {
                                Some(h) if h == prev_hash => {}
                                _ => modified += 1,
                            }
                        } else {
                            // New file
                            added += 1;
                        }
                    }
                    "delete" => {
                        // Treat as deleted (even if not present in previous index)
                        deleted += 1;
                    }
                    _ => {}
                }
            }

            Ok(GitWorkspaceStatus {
                repository_initialized: true,
                current_branch: Some(branch),
                uncommitted_changes: modified + deleted,
                untracked_files: added,
            })
        }
        .await;
        out.map_err(Into::into)
    }

    async fn list_changes(&self, workspace_id: Uuid) -> PortResult<Vec<GitChangeItem>> {
        let out: anyhow::Result<Vec<GitChangeItem>> = async {
            // If repository isn't initialized, nothing to report
            if let Some((initialized, _branch)) = self.load_repository_state(workspace_id).await? {
                if !initialized {
                    return Ok(Vec::new());
                }
            } else {
                return Ok(Vec::new());
            }

            // Use dirty set to derive changes without scanning storage
            let latest = self.latest_commit_meta(workspace_id).await?;
            let previous_index: HashMap<String, String> = latest
                .as_ref()
                .map(|c| c.file_hash_index.clone())
                .unwrap_or_default();
            let dirty = self.fetch_dirty(workspace_id).await?;

            let mut change_map: BTreeMap<String, String> = BTreeMap::new();
            for d in dirty.iter() {
                match d.op.as_str() {
                    "upsert" => {
                        if let Some(prev_hash) = previous_index.get(&d.path) {
                            // If hash unchanged and we know the new hash, skip reporting
                            match d.content_hash.as_ref() {
                                Some(h) if h == prev_hash => {
                                    change_map.remove(&d.path);
                                }
                                _ => {
                                    change_map.insert(d.path.clone(), "modified".to_string());
                                }
                            }
                        } else {
                            change_map.insert(d.path.clone(), "untracked".to_string());
                        }
                    }
                    "delete" => {
                        change_map.insert(d.path.clone(), "deleted".to_string());
                    }
                    _ => {}
                }
            }

            let changes = change_map
                .into_iter()
                .map(|(path, status)| GitChangeItem { path, status })
                .collect();
            Ok(changes)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn working_diff(&self, workspace_id: Uuid) -> PortResult<Vec<TextDiffResult>> {
        let out: anyhow::Result<Vec<TextDiffResult>> = async {
            let latest = self.latest_commit_meta(workspace_id).await?;
            let previous_index = latest
                .as_ref()
                .map(|c| c.file_hash_index.clone())
                .unwrap_or_default();
            let current = self.collect_current_state(workspace_id).await?;
            let delta = self.compute_deltas(&current, &previous_index);
            let mut results = Vec::new();

            let latest_commit_id = latest.as_ref().map(|c| c.commit_id.clone());

            for path in delta.added.iter().chain(delta.modified.iter()) {
                if let Some(snapshot) = current.get(path) {
                    if snapshot.is_text {
                        let new_bytes = self.snapshot_bytes(snapshot).await?;
                        let new_content = String::from_utf8_lossy(&new_bytes).to_string();
                        let old_bytes = match (&latest_commit_id, previous_index.get(path)) {
                            (Some(commit_id), Some(_)) => {
                                self.load_file_snapshot(workspace_id, commit_id.as_slice(), path)
                                    .await?
                            }
                            _ => None,
                        };
                        let old_text = old_bytes.and_then(|b| String::from_utf8(b).ok());
                        results.push(self.build_diff_result(
                            path,
                            old_text.as_deref(),
                            Some(&new_content),
                        ));
                    } else {
                        results.push(TextDiffResult {
                            file_path: path.clone(),
                            diff_lines: Vec::new(),
                            old_content: None,
                            new_content: None,
                        });
                    }
                }
            }

            for path in delta.deleted {
                let old_bytes = if let (Some(commit_id), Some(_)) =
                    (&latest_commit_id, previous_index.get(&path))
                {
                    self.load_file_snapshot(workspace_id, commit_id.as_slice(), &path)
                        .await?
                } else {
                    None
                };
                let old_text = old_bytes.and_then(|b| String::from_utf8(b).ok());
                results.push(self.build_diff_result(&path, old_text.as_deref(), None));
            }

            Ok(results)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn commit_diff(
        &self,
        workspace_id: Uuid,
        from: &str,
        to: &str,
    ) -> PortResult<Vec<TextDiffResult>> {
        let out: anyhow::Result<Vec<TextDiffResult>> = async {
            let from_meta = self.load_commit_meta_ref(workspace_id, from).await?;
            let to_meta = self.load_commit_meta_ref(workspace_id, to).await?;

            if let Some(to_meta_ref) = to_meta.as_ref() {
                match self
                    .commit_diff_via_packs(workspace_id, from_meta.as_ref(), to_meta_ref)
                    .await
                {
                    Ok(results) => return Ok(results),
                    Err(err) => {
                        warn!(
                            %err,
                            from = from_meta
                                .as_ref()
                                .map(|m| encode_commit_id(&m.commit_id))
                                .unwrap_or_else(|| "(root)".to_string()),
                            to = encode_commit_id(&to_meta_ref.commit_id),
                            "failed to compute commit diff from pack data, using stored snapshots"
                        );
                    }
                }
            }

            self.commit_diff_from_storage(workspace_id, from_meta.as_ref(), to_meta.as_ref())
                .await
        }
        .await;
        out.map_err(Into::into)
    }

    async fn history(&self, workspace_id: Uuid) -> PortResult<Vec<GitCommitInfo>> {
        let out: anyhow::Result<Vec<GitCommitInfo>> = async {
            let rows = sqlx::query(
                r#"SELECT commit_id, message, author_name, author_email, committed_at
               FROM git_commits
               WHERE workspace_id = $1
               ORDER BY committed_at DESC
               LIMIT 200"#,
            )
            .bind(workspace_id)
            .fetch_all(&self.pool)
            .await?;

            let history = rows
                .into_iter()
                .map(|row| {
                    let commit_id: Vec<u8> = row.get("commit_id");
                    let message: Option<String> = row.try_get("message").ok();
                    let author_name: Option<String> = row.try_get("author_name").ok();
                    let author_email: Option<String> = row.try_get("author_email").ok();
                    let committed_at: DateTime<Utc> = row.get("committed_at");
                    GitCommitInfo {
                        hash: encode_commit_id(&commit_id),
                        message: message.unwrap_or_default(),
                        author_name: author_name.unwrap_or_default(),
                        author_email: author_email.unwrap_or_default(),
                        time: committed_at,
                    }
                })
                .collect();
            Ok(history)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn sync(
        &self,
        workspace_id: Uuid,
        req: &GitSyncRequestDto,
        cfg: Option<&UserGitCfg>,
    ) -> PortResult<GitSyncOutcome> {
        self.sync_inner(workspace_id, req, cfg)
            .await
            .map_err(Into::into)
    }

    async fn import_repository(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        cfg: &UserGitCfg,
    ) -> PortResult<GitImportOutcome> {
        self.import_repository_inner(workspace_id, actor_id, cfg)
            .await
            .map_err(Into::into)
    }

    async fn pull(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        req: &GitPullRequestDto,
        cfg: &UserGitCfg,
    ) -> PortResult<GitPullResultDto> {
        self.pull_with_recovery(workspace_id, actor_id, req, cfg)
            .await
            .map_err(Into::into)
    }

    async fn head_commit(&self, workspace_id: Uuid) -> PortResult<Option<Vec<u8>>> {
        let out: anyhow::Result<Option<Vec<u8>>> = async {
            Ok(self
                .latest_commit_meta(workspace_id)
                .await?
                .map(|m| m.commit_id))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn remote_head(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> PortResult<Option<Vec<u8>>> {
        self.remote_head_inner(workspace_id, cfg)
            .await
            .map_err(Into::into)
    }

    async fn has_pending_changes(&self, workspace_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let dirty_rows = self.fetch_dirty(workspace_id).await?;
            Ok(!dirty_rows.is_empty())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn drift_since_commit(
        &self,
        workspace_id: Uuid,
        base_commit: &[u8],
    ) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let Some(meta) = self.commit_meta_by_id(workspace_id, base_commit).await? else {
                return Ok(true);
            };
            let base_index = meta.file_hash_index;
            let current_state = self.collect_current_state(workspace_id).await?;
            if base_index.len() != current_state.len() {
                return Ok(true);
            }
            for (path, snapshot) in current_state.into_iter() {
                let Some(base_hash) = base_index.get(&path) else {
                    return Ok(true);
                };
                if base_hash != &snapshot.hash {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn check_remote(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> PortResult<GitRemoteCheckDto> {
        self.check_remote_inner(workspace_id, cfg)
            .await
            .map_err(Into::into)
    }

}
