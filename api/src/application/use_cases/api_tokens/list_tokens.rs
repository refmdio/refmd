use uuid::Uuid;

use crate::application::ports::api_token_repository::{ApiToken, ApiTokenRepository};

pub struct ListApiTokens<'a, R: ApiTokenRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R> ListApiTokens<'a, R>
where
    R: ApiTokenRepository + ?Sized,
{
    pub async fn execute(&self, user_id: Uuid) -> anyhow::Result<Vec<ApiToken>> {
        self.repo.list_active(user_id).await
    }
}
