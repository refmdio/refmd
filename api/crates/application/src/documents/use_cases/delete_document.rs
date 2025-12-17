use uuid::Uuid;

use crate::documents::ports::document_repository::DocumentRepositoryTx;
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
    ) -> anyhow::Result<Option<DocumentType>> {
        self.repo.delete_owned(id, workspace_id).await
    }
}
