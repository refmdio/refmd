use crate::documents::dtos::PublicDocumentSummaryDto;
use crate::documents::ports::publishing::public_repository::PublicRepository;

pub struct ListWorkspacePublic<'a, R: PublicRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PublicRepository + ?Sized> ListWorkspacePublic<'a, R> {
    pub async fn execute(
        &self,
        workspace_slug: &str,
    ) -> anyhow::Result<Vec<PublicDocumentSummaryDto>> {
        let rows = self
            .repo
            .list_workspace_public_documents(workspace_slug)
            .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, title, updated_at, published_at)| PublicDocumentSummaryDto {
                    id,
                    title,
                    updated_at,
                    published_at,
                },
            )
            .collect())
    }
}
