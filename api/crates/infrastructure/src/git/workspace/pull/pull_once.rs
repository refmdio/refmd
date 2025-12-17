impl GitWorkspaceService {
async fn pull_once(
    &self,
    workspace_id: Uuid,
    actor_id: Uuid,
    req: &GitPullRequestDto,
    cfg: &UserGitCfg,
    skip_local_pack_restore: bool,
) -> anyhow::Result<GitPullResultDto> {
    let state = self.load_repository_state(workspace_id).await?;
    let Some((initialized, branch_default)) = state else {
        anyhow::bail!("repository not initialized");
    };
    if !initialized {
        anyhow::bail!("repository not initialized");
    }
    if cfg.repository_url.is_empty() {
        anyhow::bail!("remote not configured");
    }

    let branch = if cfg.branch_name.is_empty() {
        branch_default
    } else {
        cfg.branch_name.clone()
    };

    // Capture current workspace head before touching remote history.
    let mut local_meta = self.latest_commit_meta(workspace_id).await?;
    // After a recovery we want to treat pull as a fresh fast-forward from remote.
    if skip_local_pack_restore {
        local_meta = None;
    }
    let mut local_history_reset = false;
    let mut base_index: HashMap<String, String> = local_meta
        .as_ref()
        .map(|m| m.file_hash_index.clone())
        .unwrap_or_default();
    let mut previous_index = base_index.clone();
    let mut base_commit = local_meta.as_ref().map(|m| m.commit_id.clone());

    let temp_dir = TempDirBuilder::new()
        .prefix("git-pull-")
        .tempdir()
        .map_err(|e| anyhow::anyhow!(e))?;
    let repo = Repository::init_bare(temp_dir.path())?;
    if !skip_local_pack_restore {
        match self
            .persist_pack_chain(
                workspace_id,
                local_meta.as_ref().map(|m| m.commit_id.as_slice()),
            )
            .await?
        {
            Some((_, pack_paths)) => {
                apply_pack_files(&repo, &pack_paths)?;
            }
            None => {
                warn!(
                    workspace_id = %workspace_id,
                    "git_pull_pack_restore_missing_resetting_base"
                );
                // Storage/DB history was reset; treat as fresh pull with no local history.
                local_meta = None;
                local_history_reset = true;
                base_index.clear();
                previous_index.clear();
                base_commit = None;
            }
        }
    } else {
        info!(workspace_id = %workspace_id, "git_pull_skip_local_pack_restore");
    }

    let remote_oid = {
        let Some(head) = fetch_remote_head(&repo, cfg, &branch)? else {
            return Ok(GitPullResultDto {
                success: false,
                message: format!("branch '{branch}' not found on remote"),
                files_changed: 0,
                commit_hash: None,
                conflicts: None,
                base_commit: base_commit.clone(),
                remote_commit: None,
            });
        };
        head
    };
    let remote_commit = Some(remote_oid.as_bytes().to_vec());

    let mut local_oid = if local_history_reset {
        None
    } else {
        local_meta
            .as_ref()
            .and_then(|m| git2::Oid::from_bytes(&m.commit_id).ok())
    };
    // If workspace has no local commit recorded (fresh pull), fall back to latest known meta after bootstrap.
    if local_oid.is_none() && !skip_local_pack_restore && !local_history_reset {
        if let Some(meta) = self.latest_commit_meta(workspace_id).await? {
            base_index = meta.file_hash_index.clone();
            previous_index = base_index.clone();
            base_commit = Some(meta.commit_id.clone());
            local_oid = git2::Oid::from_bytes(&meta.commit_id).ok();
            local_meta = Some(meta);
        }
    }
    // Detect drift between latest commit and current workspace using the same dirty set as Git Changes/Status.
    let dirty_rows = self.fetch_dirty(workspace_id).await?;
    let current_state = self.collect_current_state(workspace_id).await?;
    info!(workspace_id = %workspace_id, dirty_count = dirty_rows.len(), skip_local_pack_restore = skip_local_pack_restore, "git_pull_dirty_state");

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CommitRelation {
        NoLocal,
        Same,
        LocalAhead,
        RemoteAhead,
        Diverged,
    }

    let commit_relation = if let Some(local_oid_val) = local_oid {
        if local_oid_val == remote_oid {
            CommitRelation::Same
        } else if repo.graph_descendant_of(local_oid_val, remote_oid)? {
            CommitRelation::LocalAhead
        } else if repo.graph_descendant_of(remote_oid, local_oid_val)? {
            CommitRelation::RemoteAhead
        } else {
            CommitRelation::Diverged
        }
    } else {
        CommitRelation::NoLocal
    };

    // Nothing to do when remote is identical to or behind the local head.
    if matches!(commit_relation, CommitRelation::Same | CommitRelation::LocalAhead) {
        let commit_hash = local_oid
            .as_ref()
            .map(|oid| encode_commit_id(oid.as_bytes()));
        return Ok(GitPullResultDto {
            success: true,
            message: "no remote changes".to_string(),
            files_changed: 0,
            commit_hash,
            conflicts: None,
            base_commit: base_commit.clone(),
            remote_commit: remote_commit.clone(),
        });
    }

    let remote_state = Self::pull_collect_state_from_commit(&repo, remote_oid)?;
    let remote_changed_paths_vec = Self::pull_remote_changed_paths(&base_index, &remote_state);
    let mut remote_conflicts = self
        .pull_build_conflicts_for_paths(
            workspace_id,
            &remote_changed_paths_vec,
            &current_state,
            &remote_state,
            local_meta.as_ref(),
        )
        .await?;

    // First-time pull with no local history and no dirty changes: allow fast-forward without forcing conflicts.
    if local_meta.is_none() && dirty_rows.is_empty() {
        remote_conflicts.clear();
    }

    // If commits differ but no conflict paths were detected above, fallback to diff of current vs remote trees.
    if remote_conflicts.is_empty() {
        remote_conflicts = self
            .pull_build_fallback_diff_conflicts(
                workspace_id,
                local_oid,
                remote_oid,
                &current_state,
                &remote_state,
                local_meta.as_ref(),
            )
            .await?;
    }
    let remote_changes = !remote_conflicts.is_empty();
    let remote_ahead_clean = matches!(commit_relation, CommitRelation::RemoteAhead) && dirty_rows.is_empty();
    let fast_forward_remote = matches!(commit_relation, CommitRelation::NoLocal) || remote_ahead_clean;

    // Detect overlap between remote-changed paths and dirty rows to avoid false conflicts.
    let dirty_remote_overlap = Self::pull_dirty_remote_overlap(&dirty_rows, &remote_changed_paths_vec);

    info!(
        workspace_id = %workspace_id,
        dirty_count = dirty_rows.len(),
        remote_conflict_count = remote_conflicts.len(),
        remote_changes = remote_changes,
        resolutions_count = req.resolutions.len(),
        dirty_remote_overlap = dirty_remote_overlap,
        "git_pull_debug_state"
    );

    // If workspace has dirty changes overlapping remote changes, require explicit resolutions.
    if remote_changes && dirty_remote_overlap && req.resolutions.is_empty() {
        let conflicts = if remote_conflicts.is_empty() {
            vec![GitPullConflictItemDto {
                path: "".to_string(),
                is_binary: false,
                ours: None,
                theirs: None,
                base: None,
                document_id: None,
            }]
        } else {
            remote_conflicts.clone()
        };
        return Ok(Self::pull_conflicts_detected_response(
            base_commit.clone(),
            remote_commit.clone(),
            conflicts,
        ));
    }

    // Ensure remote head commit metadata/pack exists locally for merge parent and future syncs.
    let mut remote_pack: Option<(CommitMeta, Vec<u8>)> = None;
    if self
        .commit_meta_by_id(workspace_id, remote_oid.as_bytes())
        .await?
        .is_none()
    {
        let remote_index: HashMap<String, String> = remote_state
            .iter()
            .map(|(path, snap)| (path.clone(), snap.hash.clone()))
            .collect();
        let (remote_meta, remote_pack_bytes) =
            Self::pull_build_commit_meta_and_pack(&repo, workspace_id, remote_oid, remote_index)?;
        remote_pack = Some((remote_meta, remote_pack_bytes));
    }

    // Fast-forward when there is no local history or the workspace head cleanly trails remote.
    // For fresh workspaces with dirty changes, surface conflicts instead of overwriting.
    if fast_forward_remote {
        if matches!(commit_relation, CommitRelation::NoLocal)
            && (!dirty_rows.is_empty() || !remote_conflicts.is_empty())
        {
            return Ok(Self::pull_conflicts_detected_response(
                base_commit.clone(),
                remote_commit.clone(),
                remote_conflicts.clone(),
            ));
        }
        // Ensure we have pack data for the remote head regardless of existing metadata.
        let (remote_meta, remote_pack_bytes) = if let Some((meta, pack)) = remote_pack.take() {
            (meta, pack)
        } else {
            let remote_index: HashMap<String, String> = remote_state
                .iter()
                .map(|(p, snap)| (p.clone(), snap.hash.clone()))
                .collect();
            Self::pull_build_commit_meta_and_pack(&repo, workspace_id, remote_oid, remote_index)?
        };
        return self
            .pull_fast_forward_to_remote(
                workspace_id,
                actor_id,
                base_commit.clone(),
                &previous_index,
                &remote_state,
                &remote_meta,
                Some(remote_pack_bytes.as_slice()),
            )
            .await;
    }

    // Diverged: merge local into remote (linear, parent = remote)
    let Some(local_oid_val) = local_oid else {
        anyhow::bail!("no local commit to merge");
    };

    let (meta, pack_bytes, merged_snapshots, commit_hex) = match self.pull_build_diverged_merge_commit(
        workspace_id,
        &repo,
        local_oid_val,
        remote_oid,
        req,
        &base_commit,
        &remote_commit,
    )? {
        Ok(out) => out,
        Err(dto) => return Ok(dto),
    };

    self.pull_persist_merged_commit(
        workspace_id,
        actor_id,
        &previous_index,
        base_commit,
        remote_commit,
        remote_pack.take(),
        meta,
        pack_bytes,
        merged_snapshots,
        commit_hex,
    )
    .await
}
}
impl GitWorkspaceService {
fn pull_build_diverged_merge_commit(
    &self,
    workspace_id: Uuid,
    repo: &Repository,
    local_oid_val: git2::Oid,
    remote_oid: git2::Oid,
    req: &GitPullRequestDto,
    base_commit: &Option<Vec<u8>>,
    remote_commit: &Option<Vec<u8>>,
) -> anyhow::Result<Result<(CommitMeta, Vec<u8>, HashMap<String, FileSnapshot>, String), GitPullResultDto>>
{
    // Build a synthetic "ours" commit from the current workspace state anchored to the local head
    // so dirty edits participate in the merge against remote changes.
    let synthetic_ours = self.build_synthetic_commit(workspace_id, repo, local_oid_val)?;
    let ours_commit = repo.find_commit(synthetic_ours)?;
    let remote_commit_obj = repo.find_commit(remote_oid)?;
    let index = repo.merge_commits(&ours_commit, &remote_commit_obj, None)?;

    let conflict_items = collect_conflicts(repo, &index)?;
    if !conflict_items.is_empty() && req.resolutions.is_empty() {
        return Ok(Err(Self::pull_conflicts_detected_response(
            base_commit.clone(),
            remote_commit.clone(),
            conflict_items,
        )));
    }

    // Collect conflict entries for resolution application.
    let mut conflict_entries: Vec<(String, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> =
        Vec::new();
    {
        let mut conflicts_iter = index.conflicts()?;
        while let Some(conflict) = conflicts_iter.next() {
            let conflict = conflict?;
            let path = conflict
                .our
                .as_ref()
                .or(conflict.their.as_ref())
                .or(conflict.ancestor.as_ref())
                .and_then(|e| std::str::from_utf8(&e.path).ok())
                .ok_or_else(|| anyhow!("missing conflict path"))?
                .to_string();

            let to_bytes = |entry: Option<&git2::IndexEntry>| -> anyhow::Result<Option<Vec<u8>>> {
                if let Some(e) = entry {
                    let blob = repo.find_blob(e.id)?;
                    Ok(Some(blob.content().to_vec()))
                } else {
                    Ok(None)
                }
            };

            conflict_entries.push((
                path,
                to_bytes(conflict.our.as_ref())?,
                to_bytes(conflict.their.as_ref())?,
                to_bytes(conflict.ancestor.as_ref())?,
            ));
        }
    }

    let resolution_map: std::collections::HashMap<
        String,
        &application::git::dtos::GitPullResolutionDto,
    > = req.resolutions.iter().map(|r| (r.path.clone(), r)).collect();

    // Build merged state from resolved index (stage 0) plus user resolutions.
    let mut merged_snapshots: HashMap<String, FileSnapshot> = HashMap::new();
    for entry in index.iter() {
        if index_entry_stage(&entry) != 0 {
            continue;
        }
        let path = index_entry_path(&entry)?;
        let blob = repo.find_blob(entry.id)?;
        let bytes = blob.content().to_vec();
        let hash = sha256_hex(&bytes);
        let is_text = std::str::from_utf8(&bytes).is_ok();
        merged_snapshots.insert(
            path,
            FileSnapshot {
                hash,
                data: FileSnapshotData::Inline(bytes),
                is_text,
            },
        );
    }

    let mut unresolved: Vec<GitPullConflictItemDto> = Vec::new();

    for (path, ours_bytes, theirs_bytes, base_bytes) in conflict_entries {
        let resolution = resolution_map.get(&path);
        if resolution.is_none() {
            let (mut ours_txt, ours_bin) = as_text_or_binary(path.as_str(), ours_bytes.as_ref());
            let (mut theirs_txt, theirs_bin) = as_text_or_binary(path.as_str(), theirs_bytes.as_ref());
            let (mut base_txt, base_bin) = as_text_or_binary(path.as_str(), base_bytes.as_ref());
            let is_binary = ours_bin || theirs_bin || base_bin;
            if !is_binary {
                ours_txt = strip_front_matter_body(path.as_str(), ours_txt);
                theirs_txt = strip_front_matter_body(path.as_str(), theirs_txt);
                base_txt = strip_front_matter_body(path.as_str(), base_txt);
            }
            unresolved.push(GitPullConflictItemDto {
                path: path.clone(),
                is_binary,
                ours: ours_txt,
                theirs: theirs_txt,
                base: base_txt,
                document_id: None,
            });
            continue;
        }

        let res = *resolution.unwrap();
        let selected_bytes = match res.choice.as_str() {
            "ours" => ours_bytes.clone(),
            "theirs" => theirs_bytes.clone(),
            "base" => base_bytes.clone(),
            "custom_text" => {
                let content = res
                    .content
                    .as_ref()
                    .ok_or_else(|| anyhow!("custom_text content required"))?;
                Some(content.as_bytes().to_vec())
            }
            other => anyhow::bail!("unsupported resolution choice {other}"),
        }
        .unwrap_or_default();
        let hash = sha256_hex(&selected_bytes);
        let is_text = std::str::from_utf8(&selected_bytes).is_ok();
        merged_snapshots.insert(
            path.clone(),
            FileSnapshot {
                hash,
                data: FileSnapshotData::Inline(selected_bytes),
                is_text,
            },
        );
    }

    if !unresolved.is_empty() {
        return Ok(Err(Self::pull_conflicts_detected_response(
            base_commit.clone(),
            remote_commit.clone(),
            unresolved,
        )));
    }

    // Build tree from merged snapshots without async work.
    let mut entry_map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (path, snap) in merged_snapshots.iter() {
        let bytes = match &snap.data {
            FileSnapshotData::Inline(b) => b.clone(),
            FileSnapshotData::StoragePath(_) => {
                anyhow::bail!("unexpected storage-backed snapshot during pull merge")
            }
        };
        entry_map.insert(path.clone(), bytes);
    }
    let tree_oid = build_tree_from_entries(repo, &entry_map)?;
    let tree = repo.find_tree(tree_oid)?;
    let sig = signature_from_parts("RefMD", "refmd@example.com", chrono::Utc::now())?;
    let base_parent = repo.find_commit(local_oid_val)?;
    let remote_parent = repo.find_commit(remote_oid)?;
    let parent_refs: [&git2::Commit; 2] = [&base_parent, &remote_parent];
    let commit_oid = repo.commit(
        None,
        &sig,
        &sig,
        "Merge remote changes",
        &tree,
        &parent_refs,
    )?;

    let mut file_hash_index: HashMap<String, String> = HashMap::new();
    for (path, snap) in merged_snapshots.iter() {
        file_hash_index.insert(path.clone(), snap.hash.clone());
    }

    let mut pack_builder = repo.packbuilder()?;
    pack_builder.insert_commit(commit_oid)?;
    // Include both parents to avoid missing bases when applying packs later.
    pack_builder.insert_commit(base_parent.id())?;
    pack_builder.insert_commit(remote_parent.id())?;
    let mut pack_buf = git2::Buf::new();
    pack_builder.write_buf(&mut pack_buf)?;
    let pack_bytes = pack_buf.to_vec();

    let commit_hex = encode_commit_id(commit_oid.as_bytes());
    let meta = CommitMeta {
        commit_id: commit_oid.as_bytes().to_vec(),
        // Keep workspace history linear: parent is previous workspace head.
        parent_commit_id: base_commit.clone(),
        message: Some("Merge remote changes".to_string()),
        author_name: Some("RefMD".to_string()),
        author_email: Some("refmd@example.com".to_string()),
        committed_at: chrono::Utc::now(),
        pack_key: format!("git/packs/{}/{}.pack", workspace_id, commit_hex),
        file_hash_index,
    };

    Ok(Ok((meta, pack_bytes, merged_snapshots, commit_hex)))
}
}
impl GitWorkspaceService {
async fn pull_build_fallback_diff_conflicts(
    &self,
    workspace_id: Uuid,
    local_oid: Option<git2::Oid>,
    remote_oid: git2::Oid,
    current_state: &HashMap<String, FileSnapshot>,
    remote_state: &HashMap<String, FileSnapshot>,
    local_meta: Option<&CommitMeta>,
) -> anyhow::Result<Vec<GitPullConflictItemDto>> {
    let local_oid_val = local_oid.unwrap_or(remote_oid);
    if remote_oid == local_oid_val {
        return Ok(Vec::new());
    }

    let mut all_paths: HashSet<String> = HashSet::new();
    for p in remote_state.keys() {
        all_paths.insert(p.clone());
    }
    for p in current_state.keys() {
        all_paths.insert(p.clone());
    }

    let mut remote_conflicts: Vec<GitPullConflictItemDto> = Vec::new();
    for path in all_paths {
        let remote_hash = remote_state.get(&path).map(|s| &s.hash);
        let local_hash = current_state.get(&path).map(|s| &s.hash);
        if remote_hash == local_hash {
            continue;
        }

        let item = self
            .build_conflict_item(workspace_id, &path, current_state, remote_state, local_meta)
            .await?;
        remote_conflicts.push(item);
    }

    Ok(remote_conflicts)
}
}
impl GitWorkspaceService {
fn pull_collect_state_from_commit(
    repo: &Repository,
    oid: git2::Oid,
) -> anyhow::Result<HashMap<String, FileSnapshot>> {
    let commit = repo.find_commit(oid)?;
    let tree = commit.tree()?;
    let mut out: HashMap<String, FileSnapshot> = HashMap::new();

    fn walk(
        repo: &Repository,
        tree: &git2::Tree,
        prefix: &str,
        out: &mut HashMap<String, FileSnapshot>,
    ) -> anyhow::Result<()> {
        for entry in tree.iter() {
            let name = entry.name().unwrap_or_default();
            let path = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}{name}")
            };
            match entry.kind() {
                Some(git2::ObjectType::Tree) => {
                    if let Some(sub) = entry.to_object(repo)?.as_tree() {
                        walk(repo, sub, &(path.clone() + "/"), out)?;
                    }
                }
                Some(git2::ObjectType::Blob) => {
                    let blob = repo.find_blob(entry.id())?;
                    let bytes = blob.content().to_vec();
                    let hash = sha256_hex(&bytes);
                    let is_text = std::str::from_utf8(&bytes).is_ok();
                    out.insert(
                        path,
                        FileSnapshot {
                            hash,
                            data: FileSnapshotData::Inline(bytes),
                            is_text,
                        },
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    walk(repo, &tree, "", &mut out)?;
    Ok(out)
}

fn pull_remote_changed_paths(
    base_index: &HashMap<String, String>,
    remote_state: &HashMap<String, FileSnapshot>,
) -> Vec<String> {
    let mut remote_changed_paths: HashSet<String> = HashSet::new();
    for (path, snap) in remote_state.iter() {
        if base_index.get(path) != Some(&snap.hash) {
            remote_changed_paths.insert(path.clone());
        }
    }
    for path in base_index.keys() {
        if !remote_state.contains_key(path) {
            remote_changed_paths.insert(path.clone());
        }
    }
    remote_changed_paths.into_iter().collect()
}

async fn pull_build_conflicts_for_paths(
    &self,
    workspace_id: Uuid,
    paths: &[String],
    current_state: &HashMap<String, FileSnapshot>,
    remote_state: &HashMap<String, FileSnapshot>,
    local_meta: Option<&CommitMeta>,
) -> anyhow::Result<Vec<GitPullConflictItemDto>> {
    let mut remote_conflicts: Vec<GitPullConflictItemDto> = Vec::new();
    for path in paths.iter() {
        let item = self
            .build_conflict_item(workspace_id, path, current_state, remote_state, local_meta)
            .await?;
        remote_conflicts.push(item);
    }
    Ok(remote_conflicts)
}
}
impl GitWorkspaceService {
fn pull_build_commit_meta_and_pack(
    repo: &Repository,
    workspace_id: Uuid,
    oid: git2::Oid,
    file_hash_index: HashMap<String, String>,
) -> anyhow::Result<(CommitMeta, Vec<u8>)> {
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
        Some(commit.parent_id(0)?.as_bytes().to_vec())
    } else {
        None
    };

    let mut pack_builder = repo.packbuilder()?;
    pack_builder.insert_commit(oid)?;
    if let Some(parent_id) = parent_commit_id.as_ref() {
        if let Ok(parent_oid) = git2::Oid::from_bytes(parent_id) {
            let _ = pack_builder.insert_commit(parent_oid);
        }
    }
    let mut pack_buf = git2::Buf::new();
    pack_builder.write_buf(&mut pack_buf)?;
    let pack_bytes = pack_buf.to_vec();

    let commit_hex = encode_commit_id(oid.as_bytes());
    let meta = CommitMeta {
        commit_id: oid.as_bytes().to_vec(),
        parent_commit_id,
        message,
        author_name,
        author_email,
        committed_at,
        pack_key: format!("git/packs/{}/{}.pack", workspace_id, commit_hex),
        file_hash_index,
    };

    Ok((meta, pack_bytes))
}
}
impl GitWorkspaceService {
async fn pull_fast_forward_to_remote(
    &self,
    workspace_id: Uuid,
    actor_id: Uuid,
    base_commit: Option<Vec<u8>>,
    previous_index: &HashMap<String, String>,
    remote_state: &HashMap<String, FileSnapshot>,
    remote_meta: &CommitMeta,
    remote_pack_bytes: Option<&[u8]>,
) -> anyhow::Result<GitPullResultDto> {
    if let Some(pack_bytes) = remote_pack_bytes {
        self.git_storage
            .store_pack(workspace_id, pack_bytes, remote_meta)
            .await?;
    }
    self.upsert_commit_record(workspace_id, remote_meta).await?;

    let snapshot_keys = self
        .store_commit_snapshots(workspace_id, &remote_meta.commit_id, remote_state)
        .await?;

    if let Err(err) = self
        .git_storage
        .set_latest_commit(workspace_id, Some(remote_meta))
        .await
    {
        for key in snapshot_keys.iter().rev() {
            let _ = self.git_storage.delete_blob(key).await;
        }
        return Err(err);
    }

    let mut tx = self.pool.begin().await?;
    let repo_row = sqlx::query("SELECT initialized FROM git_repository_state WHERE workspace_id = $1")
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
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT (commit_id, workspace_id) DO NOTHING"#,
    )
    .bind(remote_meta.commit_id.clone())
    .bind(remote_meta.parent_commit_id.clone())
    .bind(workspace_id)
    .bind(remote_meta.message.clone())
    .bind(remote_meta.author_name.clone())
    .bind(remote_meta.author_email.clone())
    .bind(remote_meta.committed_at)
    .bind(remote_meta.pack_key.clone())
    .bind(Json(&remote_meta.file_hash_index))
    .execute(&mut *tx)
    .await?;

    sqlx::query("UPDATE git_repository_state SET updated_at = now() WHERE workspace_id = $1")
        .bind(workspace_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let files_changed = self
        .apply_state_to_workspace(workspace_id, remote_state, previous_index)
        .await?;

    self.materialize_documents_from_state(workspace_id, actor_id, remote_state)
        .await?;
    self.apply_merged_to_documents(workspace_id, remote_state)
        .await?;
    self.clear_dirty(workspace_id).await.map_err(|err| {
        error!(
            workspace_id = %workspace_id,
            error = %err,
            "git_pull_clear_dirty_failed"
        );
        err
    })?;

    info!(
        workspace_id = %workspace_id,
        commit = %encode_commit_id(&remote_meta.commit_id),
        "git_pull_fast_forward_remote"
    );

    Ok(GitPullResultDto {
        success: true,
        message: "fast-forwarded to remote".to_string(),
        files_changed,
        commit_hash: Some(encode_commit_id(&remote_meta.commit_id)),
        conflicts: None,
        base_commit,
        remote_commit: Some(remote_meta.commit_id.clone()),
    })
}

async fn pull_persist_merged_commit(
    &self,
    workspace_id: Uuid,
    actor_id: Uuid,
    previous_index: &HashMap<String, String>,
    base_commit: Option<Vec<u8>>,
    remote_commit: Option<Vec<u8>>,
    remote_pack: Option<(CommitMeta, Vec<u8>)>,
    meta: CommitMeta,
    pack_bytes: Vec<u8>,
    merged_snapshots: HashMap<String, FileSnapshot>,
    commit_hex: String,
) -> anyhow::Result<GitPullResultDto> {
    if let Some((remote_meta, remote_pack_bytes)) = remote_pack {
        self.git_storage
            .store_pack(workspace_id, &remote_pack_bytes, &remote_meta)
            .await?;
        self.upsert_commit_record(workspace_id, &remote_meta).await?;
    }

    let snapshot_keys = self
        .store_commit_snapshots(workspace_id, &meta.commit_id, &merged_snapshots)
        .await?;

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
        let _ = self.git_storage.delete_pack(workspace_id, &meta.commit_id).await;
        for key in snapshot_keys.iter().rev() {
            let _ = self.git_storage.delete_blob(key).await;
        }
        return Err(err);
    }

    let mut tx = self.pool.begin().await?;
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
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"#,
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
    tx.commit().await?;

    let files_changed = self
        .apply_state_to_workspace(workspace_id, &merged_snapshots, previous_index)
        .await?;

    self.materialize_documents_from_state(workspace_id, actor_id, &merged_snapshots)
        .await?;
    self.apply_merged_to_documents(workspace_id, &merged_snapshots)
        .await?;

    self.clear_dirty(workspace_id).await.map_err(|err| {
        error!(
            workspace_id = %workspace_id,
            error = %err,
            "git_pull_merge_clear_dirty_failed"
        );
        err
    })?;

    Ok(GitPullResultDto {
        success: true,
        message: "remote changes merged".to_string(),
        files_changed,
        commit_hash: Some(commit_hex),
        conflicts: None,
        base_commit,
        remote_commit,
    })
}
}
impl GitWorkspaceService {
fn pull_dirty_remote_overlap(dirty_rows: &[DirtyRow], remote_changed_paths: &[String]) -> bool {
    let dirty_paths: HashSet<String> = dirty_rows.iter().map(|r| r.path.clone()).collect();
    remote_changed_paths.iter().any(|p| dirty_paths.contains(p))
}

fn pull_conflicts_detected_response(
    base_commit: Option<Vec<u8>>,
    remote_commit: Option<Vec<u8>>,
    conflicts: Vec<GitPullConflictItemDto>,
) -> GitPullResultDto {
    GitPullResultDto {
        success: false,
        message: "conflicts detected".to_string(),
        files_changed: 0,
        commit_hash: None,
        conflicts: Some(conflicts),
        base_commit,
        remote_commit,
    }
}
}
