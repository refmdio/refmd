type PullMergeOk = (CommitMeta, Vec<u8>, HashMap<String, FileSnapshot>, String);
type PullMergeResult = Result<PullMergeOk, GitPullResultDto>;
type ConflictEntry = (String, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);

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
    ) -> anyhow::Result<PullMergeResult> {
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
        let mut conflict_entries: Vec<ConflictEntry> = Vec::new();
        {
            let conflicts_iter = index.conflicts()?;
            for conflict in conflicts_iter {
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
