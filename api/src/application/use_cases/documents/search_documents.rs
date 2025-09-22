use uuid::Uuid;

use crate::application::ports::document_repository::DocumentRepository;
use crate::domain::documents::document::SearchHit;

pub struct SearchDocuments<'a, R: DocumentRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: DocumentRepository + ?Sized> SearchDocuments<'a, R> {
    pub async fn execute(
        &self,
        user_id: Uuid,
        q: Option<String>,
        limit: i64,
    ) -> anyhow::Result<Vec<SearchHit>> {
        self.repo.search_for_user(user_id, q, limit).await
    }
}
