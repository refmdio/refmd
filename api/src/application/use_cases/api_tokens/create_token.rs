use uuid::Uuid;

use crate::application::ports::api_token_repository::{ApiToken, ApiTokenRepository};
use crate::application::services::auth::api_tokens::generate_api_token;

pub struct CreateApiToken<'a, R: ApiTokenRepository + ?Sized> {
    pub repo: &'a R,
}

pub struct CreatedApiToken {
    pub token: ApiToken,
    pub plaintext: String,
}

impl<'a, R> CreateApiToken<'a, R>
where
    R: ApiTokenRepository + ?Sized,
{
    pub async fn execute(
        &self,
        user_id: Uuid,
        name: Option<&str>,
    ) -> anyhow::Result<CreatedApiToken> {
        let material = generate_api_token()?;
        let friendly_name = name
            .and_then(|n| {
                let trimmed = n.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
            .unwrap_or("Personal access token");

        let token = self
            .repo
            .create(
                user_id,
                friendly_name,
                &material.token_hash,
                &material.token_digest,
            )
            .await?;

        Ok(CreatedApiToken {
            token,
            plaintext: material.plaintext,
        })
    }
}
