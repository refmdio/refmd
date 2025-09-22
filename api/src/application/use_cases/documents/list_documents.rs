use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::domain::documents::document::Document as DomainDocument;

pub struct ListDocuments<'a, R: DocumentRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: DocumentRepository + ?Sized> ListDocuments<'a, R> {
    pub async fn execute(
        &self,
        user_id: Uuid,
        query: Option<String>,
        tag: Option<String>,
    ) -> anyhow::Result<Vec<DomainDocument>> {
        self.repo.list_for_user(user_id, query, tag).await
    }
}
