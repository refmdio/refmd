impl GitWorkspaceService {
    async fn remote_head_inner(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let state = self.load_repository_state(workspace_id).await?;
        let Some((initialized, branch_default)) = state else {
            anyhow::bail!("repository not initialized");
        };
        if !initialized {
            anyhow::bail!("repository not initialized");
        }
        if cfg.repository_url.is_empty() {
            anyhow::bail!("remote not configured");
        }
        let branch = if cfg.branch_name.is_empty() {
            branch_default
        } else {
            cfg.branch_name.clone()
        };
        let temp_dir = TempDirBuilder::new()
            .prefix("git-remote-head-")
            .tempdir()
            .map_err(|e| anyhow!(e))?;
        let repo = Repository::init_bare(temp_dir.path())?;
        let head = fetch_remote_head(&repo, cfg, &branch)?;
        Ok(head.map(|oid| oid.as_bytes().to_vec()))
    }

    async fn check_remote_inner(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<GitRemoteCheckDto> {
        if cfg.repository_url.is_empty() {
            return Ok(GitRemoteCheckDto {
                ok: true,
                message: "remote not configured".to_string(),
                reason: Some("no_remote".to_string()),
            });
        }
        let branch = cfg.branch_name.clone();
        let temp_dir = TempDirBuilder::new()
            .prefix("git-check-")
            .tempdir()
            .map_err(|e| anyhow!(e))?;
        let repo = Repository::init_bare(temp_dir.path())?;
        let result = match fetch_remote_head(&repo, cfg, &branch) {
            Ok(Some(_)) => GitRemoteCheckDto {
                ok: true,
                message: "remote reachable".to_string(),
                reason: None,
            },
            Ok(None) => GitRemoteCheckDto {
                ok: false,
                message: format!("branch '{branch}' not found on remote"),
                reason: Some("branch_missing".to_string()),
            },
            Err(err) => {
                let lower = err.to_string().to_lowercase();
                let (reason, msg) = if lower.contains("git_http_auth_redirect") {
                    (
                        Some("auth_required".to_string()),
                        "remote requires authentication or SSO approval".to_string(),
                    )
                } else if lower.contains("git_http_not_found") || lower.contains("status code: 404")
                {
                    (
                        Some("repo_not_found".to_string()),
                        "repository URL or branch not found".to_string(),
                    )
                } else {
                    (None, err.to_string())
                };
                GitRemoteCheckDto {
                    ok: false,
                    message: msg,
                    reason,
                }
            }
        };
        drop(repo);
        let _ = temp_dir.close();
        info!(workspace_id = %workspace_id, ok = %result.ok, reason = ?result.reason, "git_remote_check_completed");
        Ok(result)
    }
}
