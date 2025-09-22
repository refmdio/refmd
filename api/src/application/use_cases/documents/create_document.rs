use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::domain::documents::document::Document as DomainDocument;

pub struct CreateDocument<'a, R: DocumentRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: DocumentRepository + ?Sized> CreateDocument<'a, R> {
    pub async fn execute(
        &self,
        user_id: Uuid,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: &str,
    ) -> anyhow::Result<DomainDocument> {
        self.repo
            .create_for_user(user_id, title, parent_id, doc_type)
            .await
    }
}
