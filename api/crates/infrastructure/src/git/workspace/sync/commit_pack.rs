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
