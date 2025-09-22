use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::domain::documents::document::BacklinkInfo;

pub struct GetBacklinks<'a, R: DocumentRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: DocumentRepository + ?Sized> GetBacklinks<'a, R> {
    pub async fn execute(&self, owner_id: Uuid, doc_id: Uuid) -> anyhow::Result<Vec<BacklinkInfo>> {
        self.repo.backlinks_for(owner_id, doc_id).await
    }
}
