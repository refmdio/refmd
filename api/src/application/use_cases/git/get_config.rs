use crate::application::dto::git::GitConfigDto;
use crate::application::ports::git_repository::GitRepository;
use uuid::Uuid;

pub struct GetGitConfig<'a, R: GitRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: GitRepository + ?Sized> GetGitConfig<'a, R> {
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<Option<GitConfigDto>> {
        Ok(self.repo.get_config(user_id).await?.map(
            |(id, repository_url, branch_name, auth_type, auto_sync, created_at, updated_at)| {
                GitConfigDto {
                    id,
                    repository_url,
                    branch_name,
                    auth_type,
                    auto_sync,
                    created_at,
                    updated_at,
                }
            },
        ))
    }
}
