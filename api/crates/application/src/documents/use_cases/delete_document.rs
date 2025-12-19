use uuid::Uuid;

use crate::documents::ports::document_repository::{DocumentRepoResult, DocumentRepositoryTx};
use domain::documents::doc_type::DocumentType;

pub struct DeleteDocument<'a, R>
where
    R: DocumentRepositoryTx + ?Sized,
{
    pub repo: &'a mut R,
}

impl<'a, R> DeleteDocument<'a, R>
where
    R: DocumentRepositoryTx + ?Sized,
{
    pub async fn execute(
        &mut self,
        id: Uuid,
        workspace_id: Uuid,
    ) -> DocumentRepoResult<Option<DocumentType>> {
        self.repo.delete_owned(id, workspace_id).await
    }
}
