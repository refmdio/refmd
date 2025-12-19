use async_trait::async_trait;
use uuid::Uuid;

use crate::core::ports::errors::PortResult;
use domain::access::permissions::PermissionSet;

#[derive(Debug, Clone)]
pub struct DocumentUserAccess {
    pub workspace_id: Uuid,
    pub is_archived: bool,
    pub permissions: PermissionSet,
}

#[async_trait]
pub trait AccessRepository: Send + Sync {
    async fn resolve_user_document_access(
        &self,
        doc_id: Uuid,
        user_id: Uuid,
    ) -> PortResult<Option<DocumentUserAccess>>;
    async fn is_document_public(&self, doc_id: Uuid) -> PortResult<bool>;
    async fn is_document_archived(&self, doc_id: Uuid) -> PortResult<bool>;
}
