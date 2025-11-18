use uuid::Uuid;

use crate::application::ports::api_token_repository::ApiTokenRepository;

pub struct RevokeApiToken<'a, R: ApiTokenRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R> RevokeApiToken<'a, R>
where
    R: ApiTokenRepository + ?Sized,
{
    pub async fn execute(&self, workspace_id: Uuid, token_id: Uuid) -> anyhow::Result<bool> {
        self.repo.revoke(workspace_id, token_id).await
    }
}
