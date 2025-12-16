use uuid::Uuid;

use crate::contracts::api_tokens::ApiTokenDto;
use crate::ports::api_token_repository::ApiTokenRepository;

pub struct ListApiTokens<'a, R: ApiTokenRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R> ListApiTokens<'a, R>
where
    R: ApiTokenRepository + ?Sized,
{
    pub async fn execute(&self, workspace_id: Uuid) -> anyhow::Result<Vec<ApiTokenDto>> {
        let tokens = self.repo.list_active(workspace_id).await?;
        Ok(tokens.into_iter().map(ApiTokenDto::from).collect())
    }
}
