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
