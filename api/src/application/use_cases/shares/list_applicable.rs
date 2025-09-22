use uuid::Uuid;

use crate::application::ports::shares_repository::SharesRepository;

#[derive(Debug, Clone)]
pub struct ApplicableShareDto {
    pub token: String,
    pub permission: String,
    pub scope: String,
    pub excluded: bool,
}

pub struct ListApplicableShares<'a, R: SharesRepository + ?Sized> {
    pub repo: &'a R,
}

impl<'a, R: SharesRepository + ?Sized> ListApplicableShares<'a, R> {
    pub async fn execute(
        &self,
        owner_id: Uuid,
        doc_id: Uuid,
    ) -> anyhow::Result<Vec<ApplicableShareDto>> {
        let rows = self
            .repo
            .list_applicable_shares_for_doc(owner_id, doc_id)
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
