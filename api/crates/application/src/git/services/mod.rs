use std::sync::Arc;

use uuid::Uuid;

use crate::core::services::errors::ServiceError;
use crate::git::dtos::{GitConfigDto, UpsertGitConfigInput};
use crate::git::ports::git_repository::GitRepository;
use crate::git::use_cases::delete_config::DeleteGitConfig;
use crate::git::use_cases::get_config::GetGitConfig;
use crate::git::use_cases::upsert_config::UpsertGitConfig;
use async_trait::async_trait;

pub struct GitService {
    repo: Arc<dyn GitRepository>,
}

#[async_trait]
pub trait GitServiceFacade: Send + Sync {
    async fn get_config(&self, workspace_id: Uuid) -> Result<Option<GitConfigDto>, ServiceError>;
    async fn upsert_config(
        &self,
        workspace_id: Uuid,
        input: &UpsertGitConfigInput,
    ) -> Result<GitConfigDto, ServiceError>;
    async fn delete_config(&self, workspace_id: Uuid) -> Result<(), ServiceError>;
}

#[async_trait]
impl GitServiceFacade for GitService {
    async fn get_config(&self, workspace_id: Uuid) -> Result<Option<GitConfigDto>, ServiceError> {
        self.get_config(workspace_id).await
    }

    async fn upsert_config(
        &self,
        workspace_id: Uuid,
        input: &UpsertGitConfigInput,
    ) -> Result<GitConfigDto, ServiceError> {
        self.upsert_config(workspace_id, input).await
    }

    async fn delete_config(&self, workspace_id: Uuid) -> Result<(), ServiceError> {
        self.delete_config(workspace_id).await
    }
}

impl GitService {
    pub fn new(repo: Arc<dyn GitRepository>) -> Self {
        Self { repo }
    }

    pub async fn get_config(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<GitConfigDto>, ServiceError> {
        let uc = GetGitConfig {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id).await.map_err(ServiceError::from)
    }

    pub async fn upsert_config(
        &self,
        workspace_id: Uuid,
        input: &UpsertGitConfigInput,
    ) -> Result<GitConfigDto, ServiceError> {
        let uc = UpsertGitConfig {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, input)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn delete_config(&self, workspace_id: Uuid) -> Result<(), ServiceError> {
        let uc = DeleteGitConfig {
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id)
            .await
            .map(|_| ())
            .map_err(ServiceError::from)
    }
}
