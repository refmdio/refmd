use uuid::Uuid;

use crate::documents::ports::linkgraph_repository::LinkGraphRepository;
use domain::documents::document::OutgoingLink;

pub struct GetOutgoingLinks<'a, R: LinkGraphRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: LinkGraphRepository + ?Sized> GetOutgoingLinks<'a, R> {
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Vec<OutgoingLink>> {
        self.repo.outgoing_links_for(workspace_id, doc_id).await
    }
}
