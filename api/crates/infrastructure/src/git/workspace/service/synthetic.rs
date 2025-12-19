impl GitWorkspaceService {
    // Build a synthetic commit from the current workspace state so dirty edits participate in merges.
    fn build_synthetic_commit(
        &self,
        workspace_id: Uuid,
        repo: &Repository,
        base_oid: git2::Oid,
    ) -> anyhow::Result<git2::Oid> {
        // Collect current workspace state into blobs and index entries (supports nested paths).
        let current_state = tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(self.collect_current_state(workspace_id))
        })?;

        let mut index = repo.index()?;
        index.clear()?;

        for (path, snapshot) in current_state.iter() {
            let bytes = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(self.snapshot_bytes(snapshot))
            })?;
            let blob_oid = repo.blob(&bytes)?;

            let entry = git2::IndexEntry {
                ctime: git2::IndexTime::new(0, 0),
                mtime: git2::IndexTime::new(0, 0),
                dev: 0,
                ino: 0,
                mode: 0o100644,
                uid: 0,
                gid: 0,
                file_size: bytes.len() as u32,
                id: blob_oid,
                flags: std::cmp::min(path.len(), 0x0fff) as u16,
                flags_extended: 0,
                path: path.as_bytes().to_vec(),
            };
            index.add(&entry)?;
        }

        let tree_oid = index.write_tree_to(repo)?;
        let tree = repo.find_tree(tree_oid)?;

        // Create a synthetic commit with remote as parent to anchor the merge base.
        // Use an explicit signature so we don't rely on local git config being present.
        let sig = signature_from_parts("RefMD", "refmd@example.com", Utc::now())?;
        let commit_oid = repo.commit(
            Some("refs/heads/synthetic-workspace"),
            &sig,
            &sig,
            "workspace-state",
            &tree,
            &[&repo.find_commit(base_oid)?],
        )?;
        Ok(commit_oid)
    }
}
