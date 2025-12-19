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
