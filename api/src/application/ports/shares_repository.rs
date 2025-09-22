use async_trait::async_trait;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ShareRow {
    pub id: Uuid,
    pub token: String,
    pub permission: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub parent_share_id: Option<Uuid>,
    pub document_id: Uuid,
    pub document_type: String,
    pub document_title: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait SharesRepository: Send + Sync {
    async fn create_share(
        &self,
        owner_id: Uuid,
        document_id: Uuid,
        permission: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<(String, Uuid, String)>; // (token_saved, share_id, document_type)

    async fn list_document_shares(
        &self,
        owner_id: Uuid,
        document_id: Uuid,
    ) -> anyhow::Result<Vec<ShareRow>>;

    async fn delete_share(&self, owner_id: Uuid, token: &str) -> anyhow::Result<bool>;

    async fn validate_share_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<(Uuid, String, Option<chrono::DateTime<chrono::Utc>>, String)>>; // (document_id, permission, expires_at, title)

    async fn list_applicable_shares_for_doc(
        &self,
        owner_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Vec<(String, String, Option<chrono::DateTime<chrono::Utc>>)>>; // (token, permission, expires)

    async fn list_active_shares(&self, owner_id: Uuid) -> anyhow::Result<Vec<ShareRow>>;

    async fn resolve_share_by_token(
        &self,
        token: &str,
    ) -> anyhow::Result<
        Option<(
            Uuid,
            String,
            Option<chrono::DateTime<chrono::Utc>>,
            Uuid,
            String,
        )>,
    >; // (share_id, permission, expires_at, shared_id, shared_type)

    async fn list_subtree_nodes(
        &self,
        root_id: Uuid,
    ) -> anyhow::Result<
        Vec<(
            Uuid,
            String,
            String,
            Option<Uuid>,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )>,
    >; // (id,title,type,parent_id,created_at,updated_at)

    async fn list_materialized_children(&self, parent_share_id: Uuid) -> anyhow::Result<Vec<Uuid>>;

    async fn materialize_folder_share(&self, owner_id: Uuid, token: &str) -> anyhow::Result<i64>;
}
