use uuid::Uuid;

use crate::application::ports::public_repository::PublicRepository;

pub struct UnpublishDocument<'a, R: PublicRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PublicRepository + ?Sized> UnpublishDocument<'a, R> {
    pub async fn execute(&self, owner_id: Uuid, doc_id: Uuid) -> anyhow::Result<bool> {
        if !self.repo.is_owner_document(doc_id, owner_id).await? {
            return Ok(false);
        }
        self.repo.delete_public_document(doc_id).await
    }
}
