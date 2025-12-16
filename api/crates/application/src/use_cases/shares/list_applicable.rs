use uuid::Uuid;

use crate::contracts::shares::ApplicableShareDto;
use crate::ports::shares_repository::SharesRepository;

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
        for (token, permission, expires_at) in rows.into_iter() {
            if let Some(exp) = expires_at {
                if exp < chrono::Utc::now() {
                    continue;
                }
            }
            out.push(ApplicableShareDto {
                token,
                permission,
                scope: "document".into(),
                excluded: false,
            });
        }
        Ok(out)
    }
}
