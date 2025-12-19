impl GitWorkspaceService {
    async fn build_conflict_item(
        &self,
        workspace_id: Uuid,
        path: &str,
        current_state: &HashMap<String, FileSnapshot>,
        remote_state: &HashMap<String, FileSnapshot>,
        local_meta: Option<&CommitMeta>,
    ) -> anyhow::Result<GitPullConflictItemDto> {
        let ours_bytes = if let Some(snap) = current_state.get(path) {
            Some(self.snapshot_bytes(snap).await?)
        } else {
            None
        };
        let theirs_bytes = if let Some(snap) = remote_state.get(path) {
            Some(self.snapshot_bytes(snap).await?)
        } else {
            Some(Vec::new())
        };
        let base_bytes = if let Some(meta) = local_meta.as_ref() {
            self.load_file_snapshot(workspace_id, meta.commit_id.as_slice(), path)
                .await?
        } else {
            None
        };

        let (mut ours, ours_bin) = as_text_or_binary(path, ours_bytes.as_ref());
        let (mut theirs, theirs_bin) = as_text_or_binary(path, theirs_bytes.as_ref());
        let (mut base, base_bin) = as_text_or_binary(path, base_bytes.as_ref());
        let is_binary = ours_bin || theirs_bin || base_bin;
        if !is_binary {
            ours = strip_front_matter_body(path, ours);
            theirs = strip_front_matter_body(path, theirs);
            base = strip_front_matter_body(path, base);
        }

        Ok(GitPullConflictItemDto {
            path: path.to_string(),
            is_binary,
            ours,
            theirs,
            base,
            document_id: None,
        })
    }
}
