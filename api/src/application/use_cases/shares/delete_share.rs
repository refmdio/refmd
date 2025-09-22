use crate::application::ports::shares_repository::SharesRepository;

pub struct DeleteShare<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> DeleteShare<'a, R> {
    pub async fn execute(&self, owner_id: uuid::Uuid, token: &str) -> anyhow::Result<bool> {
        self.repo.delete_share(owner_id, token).await
    }
}
