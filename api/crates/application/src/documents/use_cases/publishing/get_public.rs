use uuid::Uuid;

use crate::documents::ports::publishing::public_repository::PublicRepository;
use domain::documents::document::Document;

pub struct GetPublicByWorkspaceAndId<'a, R: PublicRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PublicRepository + ?Sized> GetPublicByWorkspaceAndId<'a, R> {
    pub async fn execute(
        &self,
        workspace_slug: &str,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<Document>> {
        self.repo
            .get_public_meta_by_workspace_and_id(workspace_slug, doc_id)
            .await
            .map_err(Into::into)
    }
}
