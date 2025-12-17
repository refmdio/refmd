use crate::documents::ports::sharing::shares_repository::SharesRepository;

pub struct DeleteShare<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> DeleteShare<'a, R> {
    pub async fn execute(&self, workspace_id: uuid::Uuid, token: &str) -> anyhow::Result<bool> {
        self.repo.delete_share(workspace_id, token).await
    }
}
