use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;

#[derive(Debug, Clone)]
pub struct TagSummary {
    pub name: String,
    pub count: i64,
}

#[async_trait]
pub trait TagRepository: Send + Sync {
    async fn list_tags(
        &self,
        owner_id: Uuid,
        filter: Option<String>,
    ) -> PortResult<Vec<TagSummary>>;
}
