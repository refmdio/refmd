use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use domain::documents::document::Document as DomainDocument;

#[async_trait]
pub trait DocumentPathRepository: Send + Sync {
    async fn list_paths_for_user(&self, workspace_id: Uuid) -> PortResult<Vec<String>>;

    async fn get_by_owner_and_path(
        &self,
        workspace_id: Uuid,
        relative_path: &str,
    ) -> PortResult<Option<DomainDocument>>;

    async fn update_repo_path(
        &self,
        doc_id: Uuid,
        workspace_id: Uuid,
        relative_path: &str,
    ) -> PortResult<()>;
}
