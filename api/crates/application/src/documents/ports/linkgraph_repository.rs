use async_trait::async_trait;
use uuid::Uuid;

use domain::documents::document::{BacklinkInfo, OutgoingLink};

#[async_trait]
pub trait LinkGraphRepository: Send + Sync {
    async fn clear_links_for_source(&self, source_id: Uuid) -> anyhow::Result<()>;
    async fn exists_doc_for_owner(&self, doc_id: Uuid, owner_id: Uuid) -> anyhow::Result<bool>;
    async fn find_doc_id_by_owner_and_title(
        &self,
        owner_id: Uuid,
        title: &str,
    ) -> anyhow::Result<Option<Uuid>>;
    async fn upsert_link(
        &self,
        source_id: Uuid,
        target_id: Uuid,
        link_type: &str,
        link_text: Option<String>,
        position_start: i32,
        position_end: i32,
    ) -> anyhow::Result<()>;

    async fn backlinks_for(
        &self,
        workspace_id: Uuid,
        target_id: Uuid,
    ) -> anyhow::Result<Vec<BacklinkInfo>>;

    async fn outgoing_links_for(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
    ) -> anyhow::Result<Vec<OutgoingLink>>;
}
