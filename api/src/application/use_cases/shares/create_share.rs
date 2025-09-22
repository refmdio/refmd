use uuid::Uuid;

use crate::application::ports::shares_repository::SharesRepository;

pub struct CreateShare<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

pub struct CreateShareResult {
    pub token: String,
    pub document_id: Uuid,
    pub document_type: String,
}

impl<'a, R: SharesRepository + ?Sized> CreateShare<'a, R> {
    pub async fn execute(
        &self,
        owner_id: Uuid,
        document_id: Uuid,
        permission: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<CreateShareResult> {
        let (token, _share_id, dtype) = self
            .repo
            .create_share(owner_id, document_id, permission, expires_at)
            .await?;
        Ok(CreateShareResult {
            token,
            document_id,
            document_type: dtype,
        })
    }
}
