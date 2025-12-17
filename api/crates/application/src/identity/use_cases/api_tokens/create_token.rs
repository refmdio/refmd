use uuid::Uuid;

use crate::identity::dtos::{ApiTokenDto, CreatedApiTokenDto};
use crate::identity::ports::api_token_repository::ApiTokenRepository;
use crate::identity::services::api_tokens::generate_api_token;

pub struct CreateApiToken<'a, R: ApiTokenRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R> CreateApiToken<'a, R>
where
    R: ApiTokenRepository + ?Sized,
{
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        owner_id: Uuid,
        name: Option<&str>,
    ) -> anyhow::Result<CreatedApiTokenDto> {
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
                workspace_id,
                owner_id,
                friendly_name,
                &material.token_hash,
                &material.token_digest,
            )
            .await?;

        Ok(CreatedApiTokenDto {
            token: ApiTokenDto::from(token),
            plaintext: material.plaintext,
        })
    }
}
