use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::documents::document::Document as DomainDocument;
use crate::domain::documents::document::{
    BacklinkInfo as DomBacklinkInfo, OutgoingLink as DomOutgoingLink, SearchHit,
};

#[async_trait]
pub trait DocumentRepository: Send + Sync {
    async fn list_for_user(
        &self,
        user_id: Uuid,
        query: Option<String>,
        tag: Option<String>,
    ) -> anyhow::Result<Vec<DomainDocument>>;

    async fn get_by_id(&self, id: Uuid) -> anyhow::Result<Option<DomainDocument>>;

    async fn search_for_user(
        &self,
        user_id: Uuid,
        query: Option<String>,
        limit: i64,
    ) -> anyhow::Result<Vec<SearchHit>>;

    async fn create_for_user(
        &self,
        user_id: Uuid,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: &str,
    ) -> anyhow::Result<DomainDocument>;

    // parent_id: None => not provided; Some(None) => set NULL; Some(Some(uuid)) => set to value
    async fn update_title_and_parent_for_user(
        &self,
        id: Uuid,
        user_id: Uuid,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> anyhow::Result<Option<DomainDocument>>;

    // Returns Some(type) if deleted, None if not found/unauthorized
    async fn delete_owned(&self, id: Uuid, user_id: Uuid) -> anyhow::Result<Option<String>>;

    async fn backlinks_for(
        &self,
        owner_id: Uuid,
        target_id: Uuid,
    ) -> anyhow::Result<Vec<DomBacklinkInfo>>;

    async fn outgoing_links_for(
        &self,
        owner_id: Uuid,
        source_id: Uuid,
    ) -> anyhow::Result<Vec<DomOutgoingLink>>;

    // Lightweight meta for ownership-scoped queries
    async fn get_meta_for_owner(
        &self,
        doc_id: Uuid,
        owner_id: Uuid,
    ) -> anyhow::Result<Option<DocMeta>>;
}

#[derive(Debug, Clone)]
pub struct DocMeta {
    pub doc_type: String,
    pub path: Option<String>,
    pub title: String,
}
