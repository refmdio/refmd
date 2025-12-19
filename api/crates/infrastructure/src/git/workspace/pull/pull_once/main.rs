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
