struct SyncPrecompute {
    precomputed_full_entries: Option<BTreeMap<String, Vec<u8>>>,
    precomputed_upsert_bytes: BTreeMap<String, Vec<u8>>,
    changed_text_snapshots: HashMap<String, FileSnapshot>,
    next_file_hash_index: HashMap<String, String>,
    files_changed_for_response: u32,
}

impl GitWorkspaceService {
    async fn sync_inner(
        &self,
        workspace_id: Uuid,
        req: &GitSyncRequestDto,
        cfg: Option<&UserGitCfg>,
    ) -> anyhow::Result<GitSyncOutcome> {
        let state = self.load_repository_state(workspace_id).await?;
        let Some((state_initialized, state_default_branch)) = state else {
            anyhow::bail!("repository not initialized")
        };
        if !state_initialized {
            anyhow::bail!("repository not initialized")
        }

        let branch_hint = cfg
            .map(|c| c.branch_name.clone())
            .unwrap_or(state_default_branch.clone());

        let mut latest_meta = self.ensure_latest_meta(workspace_id).await?;
        if latest_meta.is_none() {
            if let Some(cfg) = cfg {
                if !cfg.repository_url.is_empty() {
                    // Bootstrap remote history; propagate errors to avoid proceeding without packs.
                    self.bootstrap_remote_history(workspace_id, cfg, branch_hint.as_str())
                        .await?;
                    latest_meta = self.ensure_latest_meta(workspace_id).await?;
                }
            }
        }

        // Resolve branch without holding a DB lock for long.
        let branch_name = cfg
            .map(|c| c.branch_name.clone())
            .unwrap_or(state_default_branch.clone());
        let force_push = req.force.unwrap_or(false);
        let force_full_scan = req.full_scan.unwrap_or(false);
        let skip_push = req.skip_push.unwrap_or(false);
        let push_required = cfg
            .as_ref()
            .map(|c| !c.repository_url.is_empty())
            .unwrap_or(false)
            && !skip_push;

        // Ensure latest commit pack exists; if missing, attempt to rebuild from storage/remote or fail early.
        if let Some(latest) = latest_meta.as_ref() {
            if self
                .git_storage
                .fetch_pack_for_commit(workspace_id, latest.commit_id.as_slice())
                .await?
                .is_none()
            {
                // Try to restore metadata and pack from storage (if pointer mismatch), else try remote bootstrap.
                warn!(
                    workspace_id = %workspace_id,
                    commit = %encode_commit_id(&latest.commit_id),
                    "git_sync_missing_latest_pack_detected"
                );
                // Attempt backfill from storage; ensure_latest_meta will also update latest pointer.
                self.ensure_storage_commit_integrity(workspace_id).await?;
                latest_meta = self.ensure_latest_meta(workspace_id).await?;
                if let Some(latest2) = latest_meta.as_ref() {
                    if self
                        .git_storage
                        .fetch_pack_for_commit(workspace_id, latest2.commit_id.as_slice())
                        .await?
                        .is_none()
                    {
                        if let Some(cfg) = cfg {
                            if !cfg.repository_url.is_empty() {
                                info!(
                                    workspace_id = %workspace_id,
                                    commit = %encode_commit_id(&latest2.commit_id),
                                    "git_sync_missing_latest_pack_bootstrap_remote"
                                );
                                self.bootstrap_remote_history(
                                    workspace_id,
                                    cfg,
                                    branch_hint.as_str(),
                                )
                                .await?;
                                latest_meta = self.ensure_latest_meta(workspace_id).await?;
                            }
                        }
                    }
                }
                if let Some(latest3) = latest_meta.as_ref() {
                    if self
                        .git_storage
                        .fetch_pack_for_commit(workspace_id, latest3.commit_id.as_slice())
                        .await?
                        .is_none()
                    {
                        anyhow::bail!(
                            "missing pack data for latest commit {}; pull and retry",
                            encode_commit_id(&latest3.commit_id)
                        );
                    }
                }
            }
        }

        let mut storage_latest = self.git_storage.latest_commit(workspace_id).await?;
        let mut storage_commit_hex = storage_latest
            .as_ref()
            .map(|m| encode_commit_id(&m.commit_id));
        let mut db_commit_hex = latest_meta.as_ref().map(|m| encode_commit_id(&m.commit_id));
        if storage_commit_hex != db_commit_hex {
            warn!(
                workspace_id = %workspace_id,
                db_commit = ?db_commit_hex,
                storage_commit = ?storage_commit_hex,
                "git_commit_pointer_mismatch_detected"
            );
            if let Some(storage_meta) = storage_latest.as_ref() {
                self.backfill_commits_from_storage(workspace_id, storage_meta)
                    .await?;
                latest_meta = self.latest_commit_meta(workspace_id).await?;
            }
            storage_latest = self.git_storage.latest_commit(workspace_id).await?;
            storage_commit_hex = storage_latest
                .as_ref()
                .map(|m| encode_commit_id(&m.commit_id));
            db_commit_hex = latest_meta.as_ref().map(|m| encode_commit_id(&m.commit_id));
            if storage_commit_hex == db_commit_hex {
                info!(
                    workspace_id = %workspace_id,
                    commit = ?storage_commit_hex,
                    "git_commit_pointer_repaired_from_storage"
                );
            } else {
                warn!(
                    workspace_id = %workspace_id,
                    db_commit = ?db_commit_hex,
                    storage_commit = ?storage_commit_hex,
                    "git_commit_pointer_attempting_realign"
                );
                self.realign_commit_history(
                    workspace_id,
                    storage_latest.clone(),
                    latest_meta.clone(),
                )
                .await?;
                latest_meta = self.ensure_latest_meta(workspace_id).await?;
                storage_latest = self.git_storage.latest_commit(workspace_id).await?;
                storage_commit_hex = storage_latest
                    .as_ref()
                    .map(|m| encode_commit_id(&m.commit_id));
                db_commit_hex = latest_meta.as_ref().map(|m| encode_commit_id(&m.commit_id));
                if storage_commit_hex == db_commit_hex {
                    info!(
                        workspace_id = %workspace_id,
                        commit = ?db_commit_hex,
                        "git_commit_pointer_repaired_by_prune"
                    );
                } else {
                    error!(
                        workspace_id = %workspace_id,
                        db_commit = ?db_commit_hex,
                        storage_commit = ?storage_commit_hex,
                        "git_commit_pointer_irreparable"
                    );
                    anyhow::bail!(
                        "repository latest commit mismatch between database ({db_commit_hex:?}) and storage ({storage_commit_hex:?})"
                    );
                }
            }
        }

        self.ensure_storage_commit_integrity(workspace_id).await?;
        latest_meta = self.latest_commit_meta(workspace_id).await?;

        let use_full_scan = force_full_scan || latest_meta.is_none();

        let previous_index = latest_meta
            .as_ref()
            .map(|c| c.file_hash_index.clone())
            .unwrap_or_default();
        let dirty_rows = self.fetch_dirty(workspace_id).await?;

        let (upserts, deletes) =
            Self::sync_build_change_sets(use_full_scan, &dirty_rows, &previous_index);

        // If still nothing to do, optionally push existing head when a remote is configured.
        if !use_full_scan && upserts.is_empty() && deletes.is_empty() {
            if push_required {
                if let Some(latest) = latest_meta.as_ref() {
                    // Ensure pack chain exists to materialize the commit for push.
                    let pack_chain = self
                        .persist_pack_chain(workspace_id, Some(latest.commit_id.as_slice()))
                        .await?;
                    if let Some((temp_dir, pack_paths)) = pack_chain {
                        let repo = Repository::init_bare(temp_dir.path())?;
                        apply_pack_files(&repo, &pack_paths)?;
                        let oid = git2::Oid::from_bytes(&latest.commit_id)?;
                        let pushed =
                            perform_push(&repo, cfg.unwrap(), &branch_name, oid, force_push)?;
                        drop(repo);
                        drop(temp_dir);
                        let _ = self.clear_dirty(workspace_id).await;
                        return Ok(GitSyncOutcome {
                            files_changed: 0,
                            commit_hash: Some(encode_commit_id(&latest.commit_id)),
                            pushed,
                            message: if pushed {
                                "push completed".to_string()
                            } else {
                                "nothing to push".to_string()
                            },
                        });
                    }
                }
            }
            // Nothing to commit/push: clear any leftover dirty and exit.
            let _ = self.clear_dirty(workspace_id).await;
            return Ok(GitSyncOutcome {
                files_changed: 0,
                commit_hash: latest_meta.map(|c| encode_commit_id(&c.commit_id)),
                pushed: false,
                message: "nothing to commit".to_string(),
            });
        }

        let committed_at = Utc::now();
        let author_name = "RefMD".to_string();
        let author_email = "refmd@example.com".to_string();
        let message = req
            .message
            .clone()
            .unwrap_or_else(|| "RefMD sync".to_string());

        let precompute = self
            .sync_precompute_tree_inputs(
                workspace_id,
                use_full_scan,
                previous_index.clone(),
                &upserts,
                &deletes,
            )
            .await?;
        let mut precomputed_full_entries = precompute.precomputed_full_entries;
        let precomputed_upsert_bytes = precompute.precomputed_upsert_bytes;
        let changed_text_snapshots = precompute.changed_text_snapshots;
        let mut next_file_hash_index = precompute.next_file_hash_index;
        let mut files_changed_for_response = precompute.files_changed_for_response;

        // Ensure full-scan entries are available before we touch libgit2 types.
        if use_full_scan && precomputed_full_entries.is_none() {
            next_file_hash_index.clear();
            let current = self.collect_current_state(workspace_id).await?;
            let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            for (path, snapshot) in current.iter() {
                let bytes = self.snapshot_bytes(snapshot).await?;
                entries.insert(path.clone(), bytes);
                next_file_hash_index.insert(path.clone(), snapshot.hash.clone());
            }
            files_changed_for_response = next_file_hash_index.len() as u32;
            precomputed_full_entries = Some(entries);
        }

        let mut previous_pack = self
            .sync_load_previous_pack_chain(workspace_id, cfg, &mut latest_meta)
            .await?;

        let (meta, pack_bytes, commit_hex, pushed) = {
            let temp_dir = TempDirBuilder::new()
                .prefix("git-sync-")
                .tempdir()
                .map_err(|e| anyhow::anyhow!(e))?;
            let repo = Repository::init_bare(temp_dir.path())?;

            if let Some((_, ref pack_paths)) = previous_pack {
                // Apply full chain to ensure delta bases are present.
                if let Err(err) = apply_pack_files(&repo, pack_paths) {
                    let lower = err.to_string().to_lowercase();
                    let missing_obj = lower.contains("missing") && lower.contains("object");
                    if !missing_obj {
                        return Err(err);
                    }

                    // Try to repair packs by re-bootstrap from remote, then retry apply once more.
                    warn!(
                        workspace_id = %workspace_id,
                        error = %err,
                        "git_sync_pack_missing_objects_retry_bootstrap"
                    );
                    if let Some(cfg) = cfg {
                        if !cfg.repository_url.is_empty() {
                            previous_pack = self
                                .sync_rebuild_pack_chain_from_remote(
                                    workspace_id,
                                    cfg,
                                    &branch_name,
                                    latest_meta.as_ref(),
                                )
                                .await?;
                            if let Some((_, ref pack_paths_retry)) = previous_pack {
                                if apply_pack_files(&repo, pack_paths_retry).is_err() {
                                    // Last resort: recover objects and retry once more.
                                    warn!(
                                        workspace_id = %workspace_id,
                                        "git_sync_pack_retry_still_missing_recovering_objects"
                                    );
                                    previous_pack = self
                                        .sync_recover_objects_and_reload_pack_chain(
                                            workspace_id,
                                            cfg,
                                            &mut latest_meta,
                                        )
                                        .await?;
                                    if let Some((_, ref pack_paths_retry2)) = previous_pack {
                                        apply_pack_files(&repo, pack_paths_retry2)?;
                                    } else {
                                        anyhow::bail!(
                                            "missing pack objects after recovery; pull/import required before sync"
                                        );
                                    }
                                }
                            } else {
                                anyhow::bail!(
                                    "missing pack objects after bootstrap; pull/import required before sync"
                                );
                            }
                        }
                    }

                    anyhow::bail!(
                        "missing pack objects for {}; pull/import to repair history",
                        latest_meta
                            .as_ref()
                            .map(|m| encode_commit_id(&m.commit_id))
                            .unwrap_or_else(|| "unknown".to_string())
                    );
                }
            }

            let full_entries = if use_full_scan {
                Some(
                    precomputed_full_entries
                        .as_ref()
                        .ok_or_else(|| anyhow!("full-scan entries missing"))?,
                )
            } else {
                None
            };
            let (meta, pack_bytes, commit_hex, pushed) = Self::sync_build_commit_pack(
                workspace_id,
                &repo,
                latest_meta.as_ref(),
                branch_name.as_str(),
                author_name.as_str(),
                author_email.as_str(),
                committed_at,
                message.as_str(),
                use_full_scan,
                full_entries,
                &deletes,
                &precomputed_upsert_bytes,
                next_file_hash_index,
                cfg,
                skip_push,
                force_push,
            )?;

            drop(repo);
            let _ = temp_dir.close();

            // files_changed_for_response computed earlier

            (meta, pack_bytes, commit_hex, pushed)
        };

        if let Some((dir, _)) = previous_pack {
            drop(dir);
        }

        // If push to a configured remote failed, do not advance local commit pointers or clear dirty state.
        // Leave files as-is so the next sync attempt will retry the push instead of treating the workspace as clean.
        if push_required && !pushed {
            return Ok(GitSyncOutcome {
                files_changed: files_changed_for_response,
                commit_hash: None,
                pushed: false,
                message: "commit created (push failed)".to_string(),
            });
        }

        self.sync_persist_commit(
            workspace_id,
            use_full_scan,
            &meta,
            &pack_bytes,
            &changed_text_snapshots,
            latest_meta.as_ref(),
        )
        .await?;
        let outcome_message = if pushed {
            "sync completed".to_string()
        } else if skip_push {
            "sync completed (push skipped)".to_string()
        } else {
            "commit created (push failed)".to_string()
        };

        Ok(GitSyncOutcome {
            files_changed: files_changed_for_response,
            commit_hash: Some(commit_hex),
            pushed,
            message: outcome_message,
        })
    }
}

impl GitWorkspaceService {
    #[allow(clippy::too_many_arguments)]
    fn sync_build_commit_pack(
        workspace_id: Uuid,
        repo: &Repository,
        latest_meta: Option<&CommitMeta>,
        branch_name: &str,
        author_name: &str,
        author_email: &str,
        committed_at: DateTime<Utc>,
        message: &str,
        use_full_scan: bool,
        full_entries: Option<&BTreeMap<String, Vec<u8>>>,
        deletes: &BTreeSet<String>,
        precomputed_upsert_bytes: &BTreeMap<String, Vec<u8>>,
        next_file_hash_index: HashMap<String, String>,
        cfg: Option<&UserGitCfg>,
        skip_push: bool,
        force_push: bool,
    ) -> anyhow::Result<(CommitMeta, Vec<u8>, String, bool)> {
        // Skip pre-fetch/verify to avoid remote redirect/auth loops; rely on push outcome.
        // Build sources from either full scan or dirty set (no awaits here).
        let tree_oid = if use_full_scan {
            let entries = full_entries.ok_or_else(|| anyhow!("full-scan entries missing"))?;
            build_tree_from_entries(repo, entries)?
        } else {
            // Incremental: reuse previous blobs for unchanged paths.
            let mut sources: BTreeMap<String, FileSource> = BTreeMap::new();
            if let Some(prev_meta) = latest_meta {
                let prev_oids = read_commit_blob_oids(repo, prev_meta.commit_id.as_slice())?;
                for (path, oid) in prev_oids {
                    sources.insert(path, FileSource::Oid(oid));
                }
            }
            for d in deletes.iter() {
                sources.remove(d);
            }
            for (path, bytes) in precomputed_upsert_bytes.iter() {
                sources.insert(path.clone(), FileSource::Bytes(bytes.clone()));
            }
            build_tree_from_sources(repo, &sources)?
        };
        let tree = repo.find_tree(tree_oid)?;

        let mut parent_commits = Vec::new();
        if let Some(prev_meta) = latest_meta {
            let parent_oid = git2::Oid::from_bytes(&prev_meta.commit_id)?;
            parent_commits.push(repo.find_commit(parent_oid)?);
        }
        let parent_refs: Vec<&Commit> = parent_commits.iter().collect();

        let branch_ref = format!("refs/heads/{}", branch_name);
        let author_sig = signature_from_parts(author_name, author_email, committed_at)?;
        let commit_oid = repo.commit(
            Some(&branch_ref),
            &author_sig,
            &author_sig,
            message,
            &tree,
            &parent_refs,
        )?;
        let commit_hex = encode_commit_id(commit_oid.as_bytes());

        let mut pack_builder = repo.packbuilder()?;
        pack_builder.insert_commit(commit_oid)?;
        // Include parent commit objects to avoid missing bases when applying packs later.
        for parent in parent_commits.iter() {
            pack_builder.insert_commit(parent.id())?;
        }
        let mut pack_buf = git2::Buf::new();
        pack_builder.write_buf(&mut pack_buf)?;
        let pack_bytes = pack_buf.to_vec();

        let message_opt = if message.trim().is_empty() {
            None
        } else {
            Some(message.to_string())
        };

        let meta = CommitMeta {
            commit_id: commit_oid.as_bytes().to_vec(),
            parent_commit_id: latest_meta.map(|c| c.commit_id.clone()),
            message: message_opt,
            author_name: Some(author_name.to_string()),
            author_email: Some(author_email.to_string()),
            committed_at,
            pack_key: format!("git/packs/{}/{}.pack", workspace_id, commit_hex.clone()),
            file_hash_index: next_file_hash_index,
        };

        let mut pushed = false;
        if let Some(cfg) = cfg {
            if !cfg.repository_url.is_empty() && !skip_push {
                // Propagate push errors so the caller can retry with force.
                pushed = perform_push(repo, cfg, branch_name, commit_oid, force_push)?;
            }
        }

        Ok((meta, pack_bytes, commit_hex, pushed))
    }
}

impl GitWorkspaceService {
    async fn sync_load_previous_pack_chain(
        &self,
        workspace_id: Uuid,
        cfg: Option<&UserGitCfg>,
        latest_meta: &mut Option<CommitMeta>,
    ) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
        let Some(prev_meta) = latest_meta.as_ref() else {
            return Ok(None);
        };
        let prev_commit_hex = encode_commit_id(&prev_meta.commit_id);
        match self
            .persist_pack_chain(workspace_id, Some(prev_meta.commit_id.as_slice()))
            .await?
        {
            Some(chain) => Ok(Some(chain)),
            None => {
                // Attempt to repair from remote and retry once.
                if let Some(cfg) = cfg {
                    if !cfg.repository_url.is_empty() {
                        warn!(
                            workspace_id = %workspace_id,
                            commit = %prev_commit_hex,
                            "git_sync_missing_pack_chain_recover"
                        );
                        self.recover_missing_objects(workspace_id, cfg).await?;
                        *latest_meta = self.ensure_latest_meta(workspace_id).await?;
                        if let Some(latest) = latest_meta.as_ref() {
                            let chain = self
                                .persist_pack_chain(
                                    workspace_id,
                                    Some(latest.commit_id.as_slice()),
                                )
                                .await?;
                            if chain.is_some() {
                                return Ok(chain);
                            }
                        }
                    }
                }
                warn!(workspace_id = %workspace_id, "git_sync_missing_pack_chain_abort");
                anyhow::bail!(
                    "missing pack data for current head {}; pull/import required before sync",
                    prev_commit_hex
                );
            }
        }
    }

    async fn sync_rebuild_pack_chain_from_remote(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
        branch_name: &str,
        latest_meta: Option<&CommitMeta>,
    ) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
        self.bootstrap_remote_history(workspace_id, cfg, branch_name)
            .await?;
        self.persist_pack_chain(
            workspace_id,
            latest_meta.map(|m| m.commit_id.as_slice()),
        )
        .await
    }

    async fn sync_recover_objects_and_reload_pack_chain(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
        latest_meta: &mut Option<CommitMeta>,
    ) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
        self.recover_missing_objects(workspace_id, cfg).await?;
        *latest_meta = self.ensure_latest_meta(workspace_id).await?;
        self.persist_pack_chain(
            workspace_id,
            latest_meta.as_ref().map(|m| m.commit_id.as_slice()),
        )
        .await
    }
}

impl GitWorkspaceService {
    fn sync_build_change_sets(
        use_full_scan: bool,
        dirty_rows: &[DirtyRow],
        previous_index: &HashMap<String, String>,
    ) -> (BTreeMap<String, DirtyUpsert>, BTreeSet<String>) {
        if use_full_scan {
            return (BTreeMap::new(), BTreeSet::new());
        }

        let mut upserts: BTreeMap<String, DirtyUpsert> = BTreeMap::new();
        let mut deletes: BTreeSet<String> = BTreeSet::new();

        for row in dirty_rows {
            match row.op.as_str() {
                "upsert" => {
                    upserts.insert(
                        row.path.clone(),
                        DirtyUpsert {
                            is_text: row.is_text,
                            content_hash: row.content_hash.clone(),
                        },
                    );
                    deletes.remove(&row.path);
                }
                "delete" => {
                    upserts.remove(&row.path);
                    deletes.insert(row.path.clone());
                }
                _ => {}
            }
        }

        upserts.retain(|path, u| match (&u.content_hash, previous_index.get(path)) {
            (Some(hnew), Some(hprev)) if hnew == hprev => false,
            _ => true,
        });

        (upserts, deletes)
    }
}

impl GitWorkspaceService {
    async fn sync_precompute_tree_inputs(
        &self,
        workspace_id: Uuid,
        use_full_scan: bool,
        previous_index: HashMap<String, String>,
        upserts: &BTreeMap<String, DirtyUpsert>,
        deletes: &BTreeSet<String>,
    ) -> anyhow::Result<SyncPrecompute> {
        // Precompute data needed for tree build and meta before creating libgit2 objects.
        // This avoids holding non-Send libgit2 types across await points.
        let mut precomputed_full_entries: Option<BTreeMap<String, Vec<u8>>> = None;
        let mut precomputed_upsert_bytes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut changed_text_snapshots: HashMap<String, FileSnapshot> = HashMap::new();
        let mut next_file_hash_index: HashMap<String, String> = previous_index;
        let files_changed_for_response: u32;

        if use_full_scan {
            next_file_hash_index.clear();
            let current = self.collect_current_state(workspace_id).await?;
            let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            for (path, snapshot) in current.iter() {
                let bytes = self.snapshot_bytes(snapshot).await?;
                entries.insert(path.clone(), bytes);
                next_file_hash_index.insert(path.clone(), snapshot.hash.clone());
            }
            files_changed_for_response = next_file_hash_index.len() as u32;
            precomputed_full_entries = Some(entries);
        } else {
            let mut stale_paths: Vec<String> = Vec::new();
            for (path, up) in upserts.iter() {
                if up.is_text {
                    match self
                        .export_markdown_for_repo_path(workspace_id, path)
                        .await?
                    {
                        Some((bytes, hash)) => {
                            precomputed_upsert_bytes.insert(path.clone(), bytes.clone());
                            next_file_hash_index.insert(path.clone(), hash.clone());
                            changed_text_snapshots.insert(
                                path.clone(),
                                FileSnapshot {
                                    hash,
                                    data: FileSnapshotData::Inline(bytes),
                                    is_text: true,
                                },
                            );
                        }
                        None => {
                            stale_paths.push(path.clone());
                        }
                    }
                    continue;
                }

                let storage_rel = format!("{}/{}", workspace_id, path);
                let abs = self.storage.absolute_from_relative(&storage_rel);
                match self.storage.read_bytes(abs.as_path()).await {
                    Ok(bytes) => {
                        precomputed_upsert_bytes.insert(path.clone(), bytes.clone());
                        let hash = match up.content_hash.as_ref() {
                            Some(h) => h.clone(),
                            None => sha256_hex(&bytes),
                        };
                        next_file_hash_index.insert(path.clone(), hash);
                    }
                    Err(e) => {
                        let skip = e
                            .downcast_ref::<io::Error>()
                            .map(|ioe| ioe.kind() == ErrorKind::NotFound)
                            .unwrap_or_else(|| e.to_string().to_lowercase().contains("not found"));
                        if skip {
                            stale_paths.push(path.clone());
                            continue;
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
            if !stale_paths.is_empty() {
                for p in stale_paths {
                    let _ = sqlx::query(
                        "DELETE FROM git_dirty_files WHERE workspace_id = $1 AND path = $2",
                    )
                    .bind(workspace_id)
                    .bind(&p)
                    .execute(&self.pool)
                    .await;
                }
            }
            for d in deletes.iter() {
                next_file_hash_index.remove(d);
            }
            files_changed_for_response = (upserts.len() + deletes.len()) as u32;
        }

        Ok(SyncPrecompute {
            precomputed_full_entries,
            precomputed_upsert_bytes,
            changed_text_snapshots,
            next_file_hash_index,
            files_changed_for_response,
        })
    }
}

impl GitWorkspaceService {
    async fn sync_persist_commit(
        &self,
        workspace_id: Uuid,
        use_full_scan: bool,
        meta: &CommitMeta,
        pack_bytes: &[u8],
        changed_text_snapshots: &HashMap<String, FileSnapshot>,
        latest_meta_for_rollback: Option<&CommitMeta>,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let repo_row =
            sqlx::query("SELECT initialized FROM git_repository_state WHERE workspace_id = $1")
                .bind(workspace_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(repo_row) = repo_row else {
            tx.rollback().await.ok();
            anyhow::bail!("repository not initialized")
        };
        let initialized: bool = repo_row.get("initialized");
        if !initialized {
            tx.rollback().await.ok();
            anyhow::bail!("repository not initialized")
        }

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
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
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

        sqlx::query("UPDATE git_repository_state SET updated_at = now() WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&mut *tx)
            .await?;

        let snapshot_keys = if use_full_scan {
            let current = self.collect_current_state(workspace_id).await?;
            match self
                .store_commit_snapshots(workspace_id, &meta.commit_id, &current)
                .await
            {
                Ok(keys) => keys,
                Err(err) => {
                    tx.rollback().await.ok();
                    return Err(err);
                }
            }
        } else {
            match self
                .store_commit_snapshots(workspace_id, &meta.commit_id, changed_text_snapshots)
                .await
            {
                Ok(keys) => keys,
                Err(err) => {
                    tx.rollback().await.ok();
                    return Err(err);
                }
            }
        };

        if let Err(err) = self
            .git_storage
            .store_pack(workspace_id, pack_bytes, meta)
            .await
        {
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            tx.rollback().await.ok();
            return Err(err);
        }

        if let Err(err) = self
            .git_storage
            .set_latest_commit(workspace_id, Some(meta))
            .await
        {
            let _ = self
                .git_storage
                .delete_pack(workspace_id, &meta.commit_id)
                .await;
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            tx.rollback().await.ok();
            return Err(err);
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
                .set_latest_commit(workspace_id, latest_meta_for_rollback)
                .await;
            return Err(err.into());
        }

        self.clear_dirty(workspace_id).await.map_err(|err| {
            error!(workspace_id = %workspace_id, error = %err, "git_import_clear_dirty_failed");
            err
        })?;
        Ok(())
    }
}

