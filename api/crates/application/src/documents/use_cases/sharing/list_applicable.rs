use uuid::Uuid;

use crate::documents::dtos::ApplicableShareDto;
use crate::documents::ports::sharing::shares_repository::SharesRepository;
use domain::documents::doc_type::DOC_TYPE_DOCUMENT;
use domain::documents::share;

pub struct ListApplicableShares<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> ListApplicableShares<'a, R> {
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Vec<ApplicableShareDto>> {
        let rows = self
            .repo
            .list_applicable_shares_for_doc(workspace_id, doc_id)
            .await?;
        let mut out = Vec::new();
        for row in rows.into_iter() {
            if share::is_expired(row.expires_at.as_ref(), chrono::Utc::now()) {
                continue;
            }
            out.push(ApplicableShareDto {
                token: row.token,
                permission: row.permission.as_str().to_string(),
                scope: DOC_TYPE_DOCUMENT.into(),
                excluded: false,
            });
        }
        Ok(out)
    }
}
