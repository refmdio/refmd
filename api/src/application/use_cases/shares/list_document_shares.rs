use uuid::Uuid;

use crate::application::ports::shares_repository::SharesRepository;

#[derive(Debug, Clone)]
pub struct ShareItemDto {
    pub id: Uuid,
    pub token: String,
    pub permission: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub document_id: Uuid,
    pub document_type: String,
    pub document_title: String,
    pub parent_share_id: Option<Uuid>,
}

pub struct ListDocumentShares<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> ListDocumentShares<'a, R> {
    pub async fn execute(
        &self,
        owner_id: Uuid,
        document_id: Uuid,
    ) -> anyhow::Result<Vec<ShareItemDto>> {
        let rows = self
            .repo
            .list_document_shares(owner_id, document_id)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| ShareItemDto {
                id: r.id,
                token: r.token.clone(),
                permission: r.permission,
                expires_at: r.expires_at,
                document_id: r.document_id,
                document_type: r.document_type,
                document_title: r.document_title,
                parent_share_id: r.parent_share_id,
            })
            .collect())
    }
}
