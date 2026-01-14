use crate::git::dtos::{GitConfigDto, UpsertGitConfigInput};
use crate::git::ports::git_repository::GitRepository;
use domain::git::auth::GitAuthType;
use uuid::Uuid;

pub struct UpsertGitConfig<'a, R>
where
    R: GitRepository + ?Sized,
{
    pub repo: &'a R,
}

impl<'a, R> UpsertGitConfig<'a, R>
where
    R: GitRepository + ?Sized,
{
    pub async fn execute(
        &self,
        workspace_id: Uuid,
        req: &UpsertGitConfigInput,
    ) -> anyhow::Result<GitConfigDto> {
        let auth_type =
            GitAuthType::parse(&req.auth_type).ok_or_else(|| anyhow::anyhow!("bad_request"))?;
        if !auth_type.validate_repository_url(&req.repository_url) {
            anyhow::bail!("bad_request");
        }

        let record = self
            .repo
            .upsert_config(
                workspace_id,
                &req.repository_url,
                req.branch_name.as_deref(),
                auth_type,
                &req.auth_data,
                req.auto_sync,
            )
            .await?;

        // Return encrypted_auth_data only for E2EE (when e2ee flag is present)
        let encrypted_auth_data = if req
            .auth_data
            .get("e2ee")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            Some(req.auth_data.clone())
        } else {
            None
        };

        Ok(GitConfigDto {
            id: record.id,
            repository_url: record.repository_url,
            branch_name: record.branch_name,
            auth_type: record.auth_type.as_str().to_string(),
            auto_sync: record.auto_sync,
            created_at: record.created_at,
            updated_at: record.updated_at,
            encrypted_auth_data,
        })
    }
}
