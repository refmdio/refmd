use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::domain::documents::document::OutgoingLink;

pub struct GetOutgoingLinks<'a, R: DocumentRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: DocumentRepository + ?Sized> GetOutgoingLinks<'a, R> {
    pub async fn execute(&self, owner_id: Uuid, doc_id: Uuid) -> anyhow::Result<Vec<OutgoingLink>> {
        self.repo.outgoing_links_for(owner_id, doc_id).await
    }
}
