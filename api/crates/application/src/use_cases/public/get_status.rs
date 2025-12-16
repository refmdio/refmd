use uuid::Uuid;

use crate::ports::public_repository::PublicRepository;
#[derive(Debug, Clone)]
pub struct PublishStatusDto {
    pub slug: String,
    pub public_url: String,
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
        if let Some((slug, workspace_slug)) =
            self.repo.get_publish_status(workspace_id, doc_id).await?
        {
            let public_url = format!("/w/{}/{}", workspace_slug, doc_id);
            Ok(Some(PublishStatusDto { slug, public_url }))
        } else {
            Ok(None)
        }
    }
}
