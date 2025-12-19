use uuid::Uuid;

use crate::documents::ports::linkgraph_repository::LinkGraphRepository;
use domain::documents::document::BacklinkInfo;

pub struct GetBacklinks<'a, R: LinkGraphRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: LinkGraphRepository + ?Sized> GetBacklinks<'a, R> {
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Vec<BacklinkInfo>> {
        self.repo
            .backlinks_for(workspace_id, doc_id)
            .await
            .map_err(Into::into)
    }
}
