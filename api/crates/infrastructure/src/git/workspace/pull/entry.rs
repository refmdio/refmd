impl GitWorkspaceService {
    async fn pull_with_recovery(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        req: &GitPullRequestDto,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<GitPullResultDto> {
        let mut recover_attempts: u8 = 0;
        let mut skip_local_pack_restore = false;
        loop {
            match self
                .pull_once(workspace_id, actor_id, req, cfg, skip_local_pack_restore)
                .await
            {
                Ok(dto) => return Ok(dto),
                Err(err) => {
                    if Self::is_missing_objects(&err) {
                        if recover_attempts < 2 {
                            recover_attempts += 1;
                            skip_local_pack_restore = true;
                            warn!(
                                workspace_id = %workspace_id,
                                attempt = %recover_attempts,
                                error = %err,
                                "git_pull_missing_objects_recovering"
                            );
                            self.recover_missing_objects(workspace_id, cfg).await?;
                            continue;
                        }
                    }
                    return Err(err);
                }
            }
        }
    }
}
