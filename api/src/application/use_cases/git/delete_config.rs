use crate::application::ports::git_repository::GitRepository;
use uuid::Uuid;

pub struct DeleteGitConfig<'a, R: GitRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: GitRepository + ?Sized> DeleteGitConfig<'a, R> {
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<bool> {
        self.repo.delete_config(user_id).await
    }
}
