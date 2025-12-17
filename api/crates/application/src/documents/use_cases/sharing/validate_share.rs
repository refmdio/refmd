use crate::documents::dtos::ShareDocumentDto;
use crate::documents::ports::sharing::shares_repository::SharesRepository;
use domain::documents::share;

pub struct ValidateShare<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> ValidateShare<'a, R> {
    pub async fn execute(&self, token: &str) -> anyhow::Result<Option<ShareDocumentDto>> {
        if let Some(doc) = self.repo.validate_share_token(token).await? {
            if share::is_expired(doc.expires_at.as_ref(), chrono::Utc::now()) {
                return Ok(None);
            }
            Ok(Some(ShareDocumentDto {
                id: doc.document_id,
                title: doc.title.into_string(),
                permission: doc.permission.as_str().to_string(),
                content: None,
            }))
        } else {
            Ok(None)
        }
    }
}
