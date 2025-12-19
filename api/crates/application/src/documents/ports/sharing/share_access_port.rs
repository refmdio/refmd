use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use domain::documents::share::{ShareContext, SharePermission};

#[async_trait]
pub trait ShareAccessPort: Send + Sync {
    async fn resolve_share_by_token(&self, token: &str) -> PortResult<Option<ShareContext>>;

    async fn get_materialized_permission(
        &self,
        parent_share_id: Uuid,
        doc_id: Uuid,
    ) -> PortResult<Option<SharePermission>>;
}
