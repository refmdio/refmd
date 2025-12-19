impl GitWorkspaceService {
    pub fn new(
        pool: PgPool,
        git_storage: Arc<dyn GitStorage>,
        storage: Arc<dyn StorageResolverPort>,
        snapshot: Arc<SnapshotService>,
        realtime: Arc<dyn RealtimeEngine>,
        docs: Arc<dyn DocumentRepository>,
        doc_paths: Arc<dyn DocumentPathRepository>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            pool,
            git_storage,
            storage,
            snapshot,
            realtime,
            docs,
            doc_paths,
        })
    }

    fn is_missing_objects(err: &anyhow::Error) -> bool {
        let msg = err.to_string().to_lowercase();
        msg.contains("missing objects") || msg.contains("packfile is missing")
    }

    async fn recover_missing_objects(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<()> {
        // Pick branch from cfg or fallback to repository state default.
        let branch = if cfg.branch_name.is_empty() {
            self.load_repository_state(workspace_id)
                .await?
                .map(|(_, default_branch)| default_branch)
                .unwrap_or_else(|| "main".to_string())
        } else {
            cfg.branch_name.clone()
        };

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
            "UPDATE git_repository_state SET initialized = true, default_branch = $2, updated_at = now() WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .bind(&branch)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let _ = self.git_storage.delete_all(workspace_id).await;
        let _ = self.git_storage.set_latest_commit(workspace_id, None).await;

        // Re-bootstrap remote history (best effort).
        let _ = self
            .bootstrap_remote_history(workspace_id, cfg, branch.as_str())
            .await;
        Ok(())
    }

    async fn load_repository_state(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<(bool, String)>> {
        let row = sqlx::query(
            "SELECT initialized, default_branch FROM git_repository_state WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| (r.get("initialized"), r.get("default_branch"))))
    }

    async fn latest_commit_meta(&self, workspace_id: Uuid) -> anyhow::Result<Option<CommitMeta>> {
        let row = sqlx::query(
            r#"SELECT commit_id, parent_commit_id, message, author_name, author_email,
                      committed_at, pack_key, file_hash_index
               FROM git_commits
               WHERE workspace_id = $1
               ORDER BY committed_at DESC
               LIMIT 1"#,
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_commit_meta).transpose()
    }

    async fn load_commit_meta_ref(
        &self,
        workspace_id: Uuid,
        rev: &str,
    ) -> anyhow::Result<Option<CommitMeta>> {
        if let Some(base) = rev.strip_suffix('^') {
            let Some(meta) = self.commit_meta_by_hex(workspace_id, base).await? else {
                return Ok(None);
            };
            if let Some(parent_id) = meta.parent_commit_id.clone() {
                return self
                    .commit_meta_by_id(workspace_id, parent_id.as_slice())
                    .await;
            }
            return Ok(None);
        }
        self.commit_meta_by_hex(workspace_id, rev).await
    }

    async fn commit_meta_by_id(
        &self,
        workspace_id: Uuid,
        commit_id: &[u8],
    ) -> anyhow::Result<Option<CommitMeta>> {
        let row = sqlx::query(
            r#"SELECT commit_id, parent_commit_id, message, author_name, author_email,
                      committed_at, pack_key, file_hash_index
               FROM git_commits
               WHERE workspace_id = $1 AND commit_id = $2
               LIMIT 1"#,
        )
        .bind(workspace_id)
        .bind(commit_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_commit_meta).transpose()
    }

    async fn commit_meta_by_hex(
        &self,
        workspace_id: Uuid,
        hex: &str,
    ) -> anyhow::Result<Option<CommitMeta>> {
        let bytes = application::git::ports::git_storage::decode_commit_id(hex)?;
        let row = sqlx::query(
            r#"SELECT commit_id, parent_commit_id, message, author_name, author_email,
                      committed_at, pack_key, file_hash_index
               FROM git_commits
               WHERE workspace_id = $1 AND commit_id = $2
               LIMIT 1"#,
        )
        .bind(workspace_id)
        .bind(bytes)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_commit_meta).transpose()
    }

    async fn ensure_latest_meta(&self, workspace_id: Uuid) -> anyhow::Result<Option<CommitMeta>> {
        if let Some(meta) = self.latest_commit_meta(workspace_id).await? {
            return Ok(Some(meta));
        }
        let Some(storage_latest) = self.git_storage.latest_commit(workspace_id).await? else {
            return Ok(None);
        };
        info!(workspace_id = %workspace_id, commit = %encode_commit_id(&storage_latest.commit_id), "git_backfill_latest_from_storage");
        self.backfill_commits_from_storage(workspace_id, &storage_latest)
            .await?;
        Ok(Some(storage_latest))
    }

    async fn bootstrap_remote_history(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
        branch: &str,
    ) -> anyhow::Result<Option<CommitMeta>> {
        let temp_dir = TempDirBuilder::new()
            .prefix("git-bootstrap-")
            .tempdir()
            .map_err(|e| anyhow!(e))?;
        let repo = Repository::init_bare(temp_dir.path())?;

        let Some(remote_head) = fetch_remote_head(&repo, cfg, branch)? else {
            return Ok(None);
        };

        let ordered = {
            let mut revwalk = repo.revwalk()?;
            revwalk.push(remote_head)?;
            revwalk.set_sorting(Sort::TOPOLOGICAL | Sort::REVERSE)?;

            let mut collected = Vec::new();
            for oid_result in revwalk {
                collected.push(oid_result?);
            }
            collected
        };

        if ordered.is_empty() {
            return Ok(None);
        }

        let pack_bytes_master = read_first_pack(repo.path())?.ok_or_else(|| {
            anyhow!(
                "remote fetch produced no pack files for workspace {}",
                workspace_id
            )
        })?;

        let mut latest_meta = self.git_storage.latest_commit(workspace_id).await?;

        for oid in ordered {
            let existing_meta = self.commit_meta_by_id(workspace_id, oid.as_bytes()).await?;
            let existing_pack = self
                .git_storage
                .fetch_pack_for_commit(workspace_id, oid.as_bytes())
                .await?;
            // Skip only when both DB row and pack already exist.
            if existing_meta.is_some() && existing_pack.is_some() {
                latest_meta = existing_meta;
                continue;
            }

            let (meta, snapshots, pack_bytes) = {
                let commit = repo.find_commit(oid)?;
                let committed_at = git_time_to_datetime(commit.time())?;
                let message = commit
                    .message()
                    .map(|m| m.trim_end_matches('\n').to_string())
                    .filter(|m| !m.trim().is_empty());
                let author = commit.author();
                let author_name = author.name().map(|s| s.to_string());
                let author_email = author.email().map(|s| s.to_string());
                let parent_commit_id = if commit.parent_count() > 0 {
                    let parent = commit.parent_id(0)?;
                    Some(parent.as_bytes().to_vec())
                } else {
                    None
                };

                let files = read_commit_files(&repo, oid.as_bytes())?;
                let mut snapshots: HashMap<String, FileSnapshot> = HashMap::new();
                let mut file_hash_index: HashMap<String, String> = HashMap::new();
                for (path, bytes) in files.into_iter() {
                    let hash = sha256_hex(&bytes);
                    let is_text = std::str::from_utf8(&bytes).is_ok();
                    file_hash_index.insert(path.clone(), hash.clone());
                    snapshots.insert(
                        path,
                        FileSnapshot {
                            hash,
                            data: FileSnapshotData::Inline(bytes),
                            is_text,
                        },
                    );
                }

                let pack_builder = repo.packbuilder()?;
                // Use the full remote pack for every commit to avoid thin-pack corruption.
                let pack_bytes = pack_bytes_master.clone();
                drop(pack_builder);

                let commit_id = oid.as_bytes().to_vec();
                let pack_key = format!(
                    "git/packs/{}/{}.pack",
                    workspace_id,
                    encode_commit_id(&commit_id)
                );

                let meta = CommitMeta {
                    commit_id,
                    parent_commit_id,
                    message,
                    author_name,
                    author_email,
                    committed_at,
                    pack_key,
                    file_hash_index,
                };

                (meta, snapshots, pack_bytes)
            };

            let prev_latest = latest_meta.clone();
            let snapshot_keys = match self
                .store_commit_snapshots(workspace_id, &meta.commit_id, &snapshots)
                .await
            {
                Ok(keys) => keys,
                Err(err) => {
                    return Err(err);
                }
            };

            if let Err(err) = self
                .git_storage
                .store_pack(workspace_id, &pack_bytes, &meta)
                .await
            {
                for key in snapshot_keys.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                return Err(err);
            }

            if let Err(err) = self
                .git_storage
                .set_latest_commit(workspace_id, Some(&meta))
                .await
            {
                let _ = self
                    .git_storage
                    .delete_pack(workspace_id, &meta.commit_id)
                    .await;
                for key in snapshot_keys.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                let _ = self
                    .git_storage
                    .set_latest_commit(workspace_id, prev_latest.as_ref())
                    .await;
                return Err(err);
            }

            let mut tx = self.pool.begin().await?;
            let upsert_res = sqlx::query(
                r#"INSERT INTO git_commits (
                        commit_id,
                        parent_commit_id,
                        workspace_id,
                        message,
                        author_name,
                        author_email,
                        committed_at,
                        pack_key,
                        file_hash_index
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                    ON CONFLICT (workspace_id, commit_id) DO UPDATE SET
                        parent_commit_id = EXCLUDED.parent_commit_id,
                        message = EXCLUDED.message,
                        author_name = EXCLUDED.author_name,
                        author_email = EXCLUDED.author_email,
                        committed_at = EXCLUDED.committed_at,
                        pack_key = EXCLUDED.pack_key,
                        file_hash_index = EXCLUDED.file_hash_index"#,
            )
            .bind(meta.commit_id.clone())
            .bind(meta.parent_commit_id.clone())
            .bind(workspace_id)
            .bind(meta.message.clone())
            .bind(meta.author_name.clone())
            .bind(meta.author_email.clone())
            .bind(meta.committed_at)
            .bind(meta.pack_key.clone())
            .bind(Json(&meta.file_hash_index))
            .execute(&mut *tx)
            .await;

            if let Err(err) = upsert_res {
                tx.rollback().await.ok();
                let _ = self
                    .git_storage
                    .delete_pack(workspace_id, &meta.commit_id)
                    .await;
                for key in snapshot_keys.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                let _ = self
                    .git_storage
                    .set_latest_commit(workspace_id, prev_latest.as_ref())
                    .await;
                return Err(err.into());
            }

            if let Err(err) = sqlx::query(
                "UPDATE git_repository_state SET updated_at = now() WHERE workspace_id = $1",
            )
            .bind(workspace_id)
            .execute(&mut *tx)
            .await
            {
                tx.rollback().await.ok();
                let _ = self
                    .git_storage
                    .delete_pack(workspace_id, &meta.commit_id)
                    .await;
                for key in snapshot_keys.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                let _ = self
                    .git_storage
                    .set_latest_commit(workspace_id, prev_latest.as_ref())
                    .await;
                return Err(err.into());
            }

            if let Err(err) = tx.commit().await {
                let _ = self
                    .git_storage
                    .delete_pack(workspace_id, &meta.commit_id)
                    .await;
                for key in snapshot_keys.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                let _ = self
                    .git_storage
                    .set_latest_commit(workspace_id, prev_latest.as_ref())
                    .await;
                return Err(err.into());
            }

            latest_meta = Some(meta);
        }

        drop(repo);
        let _ = temp_dir.close();
        self.git_storage.latest_commit(workspace_id).await
    }

    async fn backfill_commits_from_storage(
        &self,
        workspace_id: Uuid,
        latest: &CommitMeta,
    ) -> anyhow::Result<()> {
        let mut pending = Vec::new();
        let mut cursor = Some(latest.clone());
        while let Some(meta) = cursor {
            if self
                .commit_meta_by_id(workspace_id, meta.commit_id.as_slice())
                .await?
                .is_some()
            {
                break;
            }
            pending.push(meta.clone());
            cursor = match meta.parent_commit_id.clone() {
                Some(parent) => {
                    self.git_storage
                        .commit_meta(workspace_id, parent.as_slice())
                        .await?
                }
                None => None,
            };
        }
        if pending.is_empty() {
            return Ok(());
        }
        pending.reverse();
        let mut tx = self.pool.begin().await?;
        for meta in pending.into_iter() {
            sqlx::query(
                r#"INSERT INTO git_commits (
                        commit_id,
                        parent_commit_id,
                        workspace_id,
                        message,
                        author_name,
                        author_email,
                        committed_at,
                        pack_key,
                        file_hash_index
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                    ON CONFLICT (workspace_id, commit_id) DO NOTHING"#,
            )
            .bind(meta.commit_id.clone())
            .bind(meta.parent_commit_id.clone())
            .bind(workspace_id)
            .bind(meta.message.clone())
            .bind(meta.author_name.clone())
            .bind(meta.author_email.clone())
            .bind(meta.committed_at)
            .bind(meta.pack_key.clone())
            .bind(Json(&meta.file_hash_index))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn collect_commit_chain(
        &self,
        workspace_id: Uuid,
        start: CommitMeta,
    ) -> anyhow::Result<Vec<CommitMeta>> {
        let mut chain = Vec::new();
        let mut cursor = Some(start);
        while let Some(meta) = cursor {
            chain.push(meta.clone());
            cursor = match meta.parent_commit_id.clone() {
                Some(parent) => {
                    self.commit_meta_by_id(workspace_id, parent.as_slice())
                        .await?
                }
                None => None,
            };
        }
        Ok(chain)
    }

    async fn remove_commits(
        &self,
        workspace_id: Uuid,
        commits: &[CommitMeta],
    ) -> anyhow::Result<()> {
        for meta in commits {
            let commit_hex = encode_commit_id(&meta.commit_id);
            if let Err(error) = self
                .git_storage
                .delete_pack(workspace_id, &meta.commit_id)
                .await
            {
                warn!(
                    workspace_id = %workspace_id,
                    commit = %commit_hex,
                    error = ?error,
                    "git_commit_cleanup_pack_failed"
                );
            }
            for path in meta.file_hash_index.keys() {
                let key = blob_key(workspace_id, &meta.commit_id, path);
                if let Err(error) = self.git_storage.delete_blob(&key).await {
                    warn!(
                        workspace_id = %workspace_id,
                        commit = %commit_hex,
                        path = %path,
                        error = ?error,
                        "git_commit_cleanup_blob_failed"
                    );
                }
            }
            sqlx::query("DELETE FROM git_commits WHERE workspace_id = $1 AND commit_id = $2")
                .bind(workspace_id)
                .bind(meta.commit_id.clone())
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    async fn realign_commit_history(
        &self,
        workspace_id: Uuid,
        storage_latest: Option<CommitMeta>,
        db_latest: Option<CommitMeta>,
    ) -> anyhow::Result<()> {
        match (storage_latest, db_latest) {
            (Some(storage), Some(db)) => {
                if storage.commit_id == db.commit_id {
                    return Ok(());
                }
                let storage_id = storage.commit_id.clone();
                let mut cursor = Some(db.clone());
                let mut reached_storage = false;
                let mut to_prune: Vec<CommitMeta> = Vec::new();
                while let Some(meta) = cursor.clone() {
                    if meta.commit_id == storage_id {
                        reached_storage = true;
                        break;
                    }
                    to_prune.push(meta.clone());
                    cursor = match meta.parent_commit_id.clone() {
                        Some(parent) => {
                            self.commit_meta_by_id(workspace_id, parent.as_slice())
                                .await?
                        }
                        None => None,
                    };
                }
                if !reached_storage {
                    let all = self.collect_commit_chain(workspace_id, db.clone()).await?;
                    if !all.is_empty() {
                        info!(
                            workspace_id = %workspace_id,
                            removed = all.len(),
                            "git_commit_pointer_reset_db_chain"
                        );
                        self.remove_commits(workspace_id, &all).await?;
                    }
                } else if !to_prune.is_empty() {
                    info!(
                        workspace_id = %workspace_id,
                        removed = to_prune.len(),
                        "git_commit_pointer_pruned_db_commits"
                    );
                    self.remove_commits(workspace_id, &to_prune).await?;
                }
                self.backfill_commits_from_storage(workspace_id, &storage)
                    .await?;
            }
            (Some(storage), None) => {
                self.backfill_commits_from_storage(workspace_id, &storage)
                    .await?;
            }
            (None, Some(db)) => {
                let all = self.collect_commit_chain(workspace_id, db).await?;
                if !all.is_empty() {
                    info!(
                        workspace_id = %workspace_id,
                        removed = all.len(),
                        "git_commit_pointer_dropped_db_history"
                    );
                    self.remove_commits(workspace_id, &all).await?;
                }
            }
            (None, None) => {}
        }
        Ok(())
    }

    async fn prune_commits_from_head(
        &self,
        workspace_id: Uuid,
        commits: &[CommitMeta],
    ) -> anyhow::Result<()> {
        if commits.is_empty() {
            return Ok(());
        }
        self.remove_commits(workspace_id, commits).await?;
        let new_latest = self.latest_commit_meta(workspace_id).await?;
        self.git_storage
            .set_latest_commit(workspace_id, new_latest.as_ref())
            .await?;
        Ok(())
    }

    async fn ensure_storage_commit_integrity(&self, workspace_id: Uuid) -> anyhow::Result<()> {
        loop {
            let Some(latest) = self.latest_commit_meta(workspace_id).await? else {
                self.git_storage
                    .set_latest_commit(workspace_id, None)
                    .await?;
                return Ok(());
            };
            let chain = self
                .collect_commit_chain(workspace_id, latest.clone())
                .await?;
            let mut missing_idx: Option<usize> = None;
            for (idx, meta) in chain.iter().enumerate() {
                match self
                    .git_storage
                    .commit_meta(workspace_id, meta.commit_id.as_slice())
                    .await?
                {
                    Some(_) => continue,
                    None => {
                        missing_idx = Some(idx);
                        break;
                    }
                }
            }
            if let Some(idx) = missing_idx {
                let to_remove: Vec<CommitMeta> = chain[..=idx].to_vec();
                info!(
                    workspace_id = %workspace_id,
                    removed = to_remove.len(),
                    missing_commit = %encode_commit_id(&chain[idx].commit_id),
                    "git_commit_pointer_pruned_missing_storage_meta"
                );
                self.prune_commits_from_head(workspace_id, &to_remove)
                    .await?;
                continue;
            }
            break;
        }
        Ok(())
    }

}
