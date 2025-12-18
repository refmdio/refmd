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
