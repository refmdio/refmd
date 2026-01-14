use std::sync::Arc;

use application::git::services::GitService;
use infrastructure::core::db::PgPool;

pub struct GitStack {
    pub service: Arc<GitService>,
    pub repo: Arc<dyn application::git::ports::git_repository::GitRepository>,
}

pub fn build_git_stack(
    cfg: &crate::config::Config,
    pool: &PgPool,
) -> anyhow::Result<GitStack> {
    let git_repo = Arc::new(
        infrastructure::git::db::repositories::git_repository_sqlx::SqlxGitRepository::new(
            pool.clone(),
            cfg.encryption_key.clone(),
        ),
    );
    let git_service = Arc::new(GitService::new(git_repo.clone()));

    Ok(GitStack {
        service: git_service,
        repo: git_repo,
    })
}
