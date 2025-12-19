impl GitWorkspaceService {
    async fn sync_load_previous_pack_chain(
        &self,
        workspace_id: Uuid,
        cfg: Option<&UserGitCfg>,
        latest_meta: &mut Option<CommitMeta>,
    ) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
        let Some(prev_meta) = latest_meta.as_ref() else {
            return Ok(None);
        };
        let prev_commit_hex = encode_commit_id(&prev_meta.commit_id);
        match self
            .persist_pack_chain(workspace_id, Some(prev_meta.commit_id.as_slice()))
            .await?
        {
            Some(chain) => Ok(Some(chain)),
            None => {
                // Attempt to repair from remote and retry once.
                if let Some(cfg) = cfg {
                    if !cfg.repository_url.is_empty() {
                        warn!(
                            workspace_id = %workspace_id,
                            commit = %prev_commit_hex,
                            "git_sync_missing_pack_chain_recover"
                        );
                        self.recover_missing_objects(workspace_id, cfg).await?;
                        *latest_meta = self.ensure_latest_meta(workspace_id).await?;
                        if let Some(latest) = latest_meta.as_ref() {
                            let chain = self
                                .persist_pack_chain(
                                    workspace_id,
                                    Some(latest.commit_id.as_slice()),
                                )
                                .await?;
                            if chain.is_some() {
                                return Ok(chain);
                            }
                        }
                    }
                }
                warn!(workspace_id = %workspace_id, "git_sync_missing_pack_chain_abort");
                anyhow::bail!(
                    "missing pack data for current head {}; pull/import required before sync",
                    prev_commit_hex
                );
            }
        }
    }

    async fn sync_rebuild_pack_chain_from_remote(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
        branch_name: &str,
        latest_meta: Option<&CommitMeta>,
    ) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
        self.bootstrap_remote_history(workspace_id, cfg, branch_name)
            .await?;
        self.persist_pack_chain(
            workspace_id,
            latest_meta.map(|m| m.commit_id.as_slice()),
        )
        .await
    }

    async fn sync_recover_objects_and_reload_pack_chain(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
        latest_meta: &mut Option<CommitMeta>,
    ) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
        self.recover_missing_objects(workspace_id, cfg).await?;
        *latest_meta = self.ensure_latest_meta(workspace_id).await?;
        self.persist_pack_chain(
            workspace_id,
            latest_meta.as_ref().map(|m| m.commit_id.as_slice()),
        )
        .await
    }
}
