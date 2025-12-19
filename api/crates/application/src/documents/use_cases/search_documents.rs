use uuid::Uuid;

use crate::documents::ports::document_repository::{DocumentRepoResult, DocumentRepository};
use domain::documents::document::SearchHit;

pub struct SearchDocuments<'a, R: DocumentRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: DocumentRepository + ?Sized> SearchDocuments<'a, R> {
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        q: Option<String>,
        limit: i64,
    ) -> DocumentRepoResult<Vec<SearchHit>> {
        self.repo.search_for_user(workspace_id, q, limit).await
    }
}
