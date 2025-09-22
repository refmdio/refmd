use crate::application::dto::shares::ShareDocumentDto;
use crate::application::ports::shares_repository::SharesRepository;

pub struct ValidateShare<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> ValidateShare<'a, R> {
    pub async fn execute(&self, token: &str) -> anyhow::Result<Option<ShareDocumentDto>> {
        if let Some((document_id, permission, expires_at, title)) =
            self.repo.validate_share_token(token).await?
        {
            if let Some(exp) = expires_at {
                if exp < chrono::Utc::now() {
                    return Ok(None);
                }
            }
            Ok(Some(ShareDocumentDto {
                id: document_id,
                title,
                permission,
                content: None,
            }))
        } else {
            Ok(None)
        }
    }
}
