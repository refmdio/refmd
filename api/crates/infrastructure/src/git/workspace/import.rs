impl GitWorkspaceService {
    async fn import_repository_inner(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<GitImportOutcome> {
        // Suppress dirty tracking globally during import so filesystem watcher/ingest won't re-mark files.
        let _global_dirty_guard = crate::storage::suppress_git_dirty_global();
        let branch = if cfg.branch_name.is_empty() {
            "main".to_string()
        } else {
            cfg.branch_name.clone()
        };
        self.ensure_repository(workspace_id, &branch).await?;

        let previous_index = self
            .latest_commit_meta(workspace_id)
            .await?
            .map(|m| m.file_hash_index)
            .unwrap_or_default();

        // Populate storage and DB with remote history; surface errors so we don't proceed with missing packs.
        self.bootstrap_remote_history(workspace_id, cfg, branch.as_str())
            .await?;
        let latest = self.ensure_latest_meta(workspace_id).await?;
        let Some(latest_meta) = latest else {
            return Ok(GitImportOutcome {
                files_changed: 0,
                commit_hash: None,
                docs_created: 0,
                attachments_created: 0,
                message: "remote has no commits".to_string(),
            });
        };

        let state = self
            .state_from_commit_meta(workspace_id, &latest_meta)
            .await?;
        let files_changed = crate::storage::suppress_git_dirty(async {
            self.apply_state_to_workspace(workspace_id, &state, &previous_index)
                .await
        })
        .await?;

        // Materialize documents and attachments from imported state; surface failures so Import can fail loudly.
        let (docs_created, attachments_created) =
            crate::storage::suppress_git_dirty(async {
                self.materialize_documents_from_state(workspace_id, actor_id, &state)
                    .await
            })
            .await?;

        self.apply_merged_to_documents(workspace_id, &state).await?;
        self.clear_dirty(workspace_id).await.map_err(|err| {
            error!(workspace_id = %workspace_id, error = %err, "git_import_clear_dirty_failed");
            err
        })?;

        Ok(GitImportOutcome {
            files_changed,
            docs_created,
            attachments_created,
            commit_hash: Some(encode_commit_id(&latest_meta.commit_id)),
            message: "import completed".to_string(),
        })
    }
}
