use uuid::Uuid;

use crate::documents::ports::publishing::public_repository::PublicRepository;
#[derive(Debug, Clone)]
pub struct PublishStatusDto {
    pub slug: String,
    pub public_url: String,
    pub noindex: bool,
}

pub struct GetPublishStatus<'a, R: PublicRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: PublicRepository + ?Sized> GetPublishStatus<'a, R> {
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Option<PublishStatusDto>> {
        if let Some(status) = self.repo.get_publish_status(workspace_id, doc_id).await? {
            let public_url = format!("/w/{}/{}", status.workspace_slug, doc_id);
            Ok(Some(PublishStatusDto {
                slug: status.slug,
                public_url,
                noindex: status.noindex,
            }))
        } else {
            Ok(None)
        }
    }
}
