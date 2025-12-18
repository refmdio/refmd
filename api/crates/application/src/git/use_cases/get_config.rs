use crate::git::dtos::GitConfigDto;
use crate::git::ports::git_repository::GitRepository;
use uuid::Uuid;

pub struct GetGitConfig<'a, R: GitRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: GitRepository + ?Sized> GetGitConfig<'a, R> {
    pub async fn execute(&self, workspace_id: Uuid) -> anyhow::Result<Option<GitConfigDto>> {
        Ok(self.repo.get_config(workspace_id).await?.map(|record| GitConfigDto {
            id: record.id,
            repository_url: record.repository_url,
            branch_name: record.branch_name,
            auth_type: record.auth_type.as_str().to_string(),
            auto_sync: record.auto_sync,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }))
    }
}
