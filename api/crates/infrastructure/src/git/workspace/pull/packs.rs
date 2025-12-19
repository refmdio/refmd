impl GitWorkspaceService {
    async fn persist_pack_chain(
        &self,
        workspace_id: Uuid,
        until: Option<&[u8]>,
    ) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
        // Attempt to rebuild pack chain from stored snapshots if packs are missing or corrupted.
        async fn rebuild_from_snapshots(
            svc: &GitWorkspaceService,
            workspace_id: Uuid,
            until: Option<&[u8]>,
        ) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
            // Collect commit metas from oldest to newest
            let mut chain: Vec<CommitMeta> = Vec::new();
            let mut cursor = match until {
                Some(id) => svc.commit_meta_by_id(workspace_id, id).await?,
                None => svc.latest_commit_meta(workspace_id).await?,
            };
            while let Some(meta) = cursor {
                chain.push(meta.clone());
                if let Some(parent) = meta.parent_commit_id.as_ref() {
                    cursor = svc.commit_meta_by_id(workspace_id, parent).await?;
                } else {
                    break;
                }
            }
            if chain.is_empty() {
                return Ok(None);
            }
            chain.reverse();

            type PreparedEntry = (String, Vec<u8>);
            type PreparedCommit = (CommitMeta, Vec<PreparedEntry>);

            // Preload snapshots async
            let mut prepared: Vec<PreparedCommit> = Vec::new();
            for meta in chain.iter() {
                let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
                for path in meta.file_hash_index.keys() {
                    let Some(bytes) = svc
                        .load_file_snapshot(workspace_id, meta.commit_id.as_slice(), path)
                        .await?
                    else {
                        anyhow::bail!(
                            "missing snapshot blob for {} at commit {}",
                            path,
                            encode_commit_id(&meta.commit_id)
                        );
                    };
                    entries.push((path.clone(), bytes));
                }
                prepared.push((meta.clone(), entries));
            }

            // Build packs synchronously to avoid Send issues with git2 types
            let (temp_dir, pack_paths) = tokio::task::block_in_place(|| -> anyhow::Result<_> {
                let temp_dir = tempfile::tempdir()?;
                let repo = Repository::init_bare(temp_dir.path())?;
                let mut built_commits: HashMap<Vec<u8>, git2::Oid> = HashMap::new();
                let mut pack_paths: Vec<PathBuf> = Vec::new();

                for (meta, entries) in prepared.into_iter() {
                    let mut builder = repo.treebuilder(None)?;
                    for (path, bytes) in entries.iter() {
                        let blob_oid = repo.blob(bytes)?;
                        builder.insert(path, blob_oid, FileMode::Blob.into())?;
                    }
                    let tree_oid = builder.write()?;
                    let tree = repo.find_tree(tree_oid)?;

                    let sig = signature_from_parts(
                        meta.author_name.as_deref().unwrap_or("RefMD"),
                        meta.author_email.as_deref().unwrap_or("refmd@example.com"),
                        meta.committed_at,
                    )?;
                    let mut parents = Vec::new();
                    if let Some(parent) = meta.parent_commit_id.as_ref() {
                        if let Some(existing) = built_commits.get(parent) {
                            parents.push(repo.find_commit(*existing)?);
                        }
                    }
                    let parent_refs: Vec<&Commit> = parents.iter().collect();
                    let commit_oid = repo.commit(
                        None,
                        &sig,
                        &sig,
                        meta.message
                            .as_deref()
                            .unwrap_or("Recovered commit from snapshots"),
                        &tree,
                        &parent_refs,
                    )?;
                    if commit_oid.as_bytes() != meta.commit_id.as_slice() {
                        anyhow::bail!(
                            "reconstructed commit id mismatch for {}",
                            encode_commit_id(&meta.commit_id)
                        );
                    }
                    built_commits.insert(meta.commit_id.clone(), commit_oid);

                    let mut pack_builder = repo.packbuilder()?;
                    pack_builder.insert_commit(commit_oid)?;
                    for p in parents.iter() {
                        pack_builder.insert_commit(p.id())?;
                    }
                    let mut pack_buf = git2::Buf::new();
                    pack_builder.write_buf(&mut pack_buf)?;
                    let pack_bytes = pack_buf.to_vec();

                    let pack_path = temp_dir
                        .path()
                        .join(format!("{:08}.pack", pack_paths.len()));
                    std::fs::write(&pack_path, &pack_bytes)?;
                    pack_paths.push(pack_path);
                }

                Ok((temp_dir, pack_paths))
            })?;

            // Persist rebuilt packs and metas back to storage
            for (idx, meta) in chain.iter().enumerate() {
                let pack_bytes = std::fs::read(&pack_paths[idx])?;
                svc.git_storage
                    .store_pack(workspace_id, &pack_bytes, meta)
                    .await?;
                svc.upsert_commit_record(workspace_id, meta).await?;
                let _ = svc
                    .git_storage
                    .set_latest_commit(workspace_id, Some(meta))
                    .await;
            }

            Ok(Some((temp_dir, pack_paths)))
        }

        let mut attempts = 0;
        loop {
            match self.git_storage.load_pack_chain(workspace_id, until).await {
                Ok(mut stream) => {
                    let temp_dir = tempfile::tempdir()?;
                    let mut pack_paths = Vec::new();
                    let mut index: usize = 0;
                    while let Some(pack) = stream.next().await {
                        let pack = pack?;
                        let path = temp_dir.path().join(format!("{:08}.pack", index));
                        tokio::fs::write(&path, &pack.bytes).await?;
                        pack_paths.push(path);
                        index += 1;
                    }
                    if pack_paths.is_empty() {
                        return Ok(None);
                    } else {
                        return Ok(Some((temp_dir, pack_paths)));
                    }
                }
                Err(err) => {
                    let err_str = err.to_string();
                    let is_missing_objects = err_str.to_lowercase().contains("missing")
                        && err_str.to_lowercase().contains("object");
                    if let Some(rebuilt) = rebuild_from_snapshots(self, workspace_id, until).await?
                    {
                        return Ok(Some(rebuilt));
                    }
                    if attempts == 0 {
                        if let Some(commit_hex) = missing_metadata_commit(&err) {
                            match self
                                .repair_missing_commit_metadata(workspace_id, &commit_hex)
                                .await
                            {
                                Ok(_) => {
                                    attempts += 1;
                                    continue;
                                }
                                Err(repair_err) => {
                                    warn!(
                                        workspace_id = %workspace_id,
                                        commit = %commit_hex,
                                        error = ?repair_err,
                                        "git_commit_metadata_repair_failed"
                                    );
                                }
                            }
                        }
                        // If pack is missing objects, fall back by resetting git storage pointer and DB history.
                        if is_missing_objects {
                            warn!(
                                workspace_id = %workspace_id,
                                error = %err,
                                "git_pack_missing_objects_detected_resetting_history"
                            );
                            // Drop storage latest pointer and DB commits for this workspace.
                            let _ = self.git_storage.set_latest_commit(workspace_id, None).await;
                            let _ = sqlx::query("DELETE FROM git_commits WHERE workspace_id = $1")
                                .bind(workspace_id)
                                .execute(&self.pool)
                                .await;
                            return Ok(None);
                        }
                    }
                    return Err(err);
                }
            }
        }
    }
}
