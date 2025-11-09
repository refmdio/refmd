use uuid::Uuid;

use crate::application::dto::api_tokens::ApiTokenDto;
use crate::application::ports::api_token_repository::ApiTokenRepository;

pub struct ListApiTokens<'a, R: ApiTokenRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R> ListApiTokens<'a, R>
where
    R: ApiTokenRepository + ?Sized,
{
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<Vec<ApiTokenDto>> {
        let tokens = self.repo.list_active(user_id).await?;
        Ok(tokens.into_iter().map(ApiTokenDto::from).collect())
    }
}
