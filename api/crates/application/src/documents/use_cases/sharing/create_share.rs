use uuid::Uuid;

use crate::documents::ports::sharing::shares_repository::SharesRepository;
use domain::documents::doc_type::DocumentType;
use domain::documents::share::SharePermission;

pub struct CreateShare<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

pub struct CreateShareResult {
    pub token: String,
    pub document_id: Uuid,
    pub document_type: DocumentType,
}

impl<'a, R: SharesRepository + ?Sized> CreateShare<'a, R> {
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        document_id: Uuid,
        permission: SharePermission,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<CreateShareResult> {
        let created = self
            .repo
            .create_share(workspace_id, actor_id, document_id, permission, expires_at)
            .await?;
        Ok(CreateShareResult {
            token: created.token,
            document_id,
            document_type: created.document_type,
        })
    }
}
