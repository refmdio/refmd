use uuid::Uuid;

use crate::ports::document_repository::{DocumentListState, DocumentRepository};
use domain::documents::document::Document as DomainDocument;

pub struct ListDocuments<'a, R: DocumentRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: DocumentRepository + ?Sized> ListDocuments<'a, R> {
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        query: Option<String>,
        tag: Option<String>,
        state: DocumentListState,
    ) -> anyhow::Result<Vec<DomainDocument>> {
        self.repo
            .list_for_user(workspace_id, query, tag, state)
            .await
    }
}
