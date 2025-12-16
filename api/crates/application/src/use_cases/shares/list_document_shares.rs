use uuid::Uuid;

use crate::contracts::shares::ShareItemDto;
use crate::ports::shares_repository::SharesRepository;

pub struct ListDocumentShares<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> ListDocumentShares<'a, R> {
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        document_id: Uuid,
    ) -> anyhow::Result<Vec<ShareItemDto>> {
        let rows = self
            .repo
            .list_document_shares(workspace_id, document_id)
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
                parent_share_id: r.parent_share_id,
            })
            .collect())
    }
}
