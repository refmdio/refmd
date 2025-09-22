use uuid::Uuid;

use crate::application::dto::shares::ActiveShareItemDto;
use crate::application::ports::shares_repository::SharesRepository;

pub struct ListActiveShares<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> ListActiveShares<'a, R> {
    pub async fn execute(&self, owner_id: Uuid) -> anyhow::Result<Vec<ActiveShareItemDto>> {
        let rows = self.repo.list_active_shares(owner_id).await?;
        let mut items = Vec::with_capacity(rows.len());
        for r in rows.into_iter() {
            items.push(ActiveShareItemDto {
                id: r.id,
                token: r.token,
                permission: r.permission,
                expires_at: r.expires_at,
                created_at: r.created_at,
                document_id: r.document_id,
                document_title: r.document_title,
                document_type: r.document_type,
                parent_share_id: r.parent_share_id,
            });
        }
        Ok(items)
    }
}
