use std::sync::Arc;

use uuid::Uuid;

use crate::application::dto::auth::UserDto;
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::plugin_asset_store::PluginAssetStore;
use crate::application::ports::plugin_installation_repository::PluginInstallationRepository;
use crate::application::ports::plugin_repository::PluginRepository;
use crate::application::ports::storage_projection_queue::StorageProjectionQueue;
use crate::application::ports::user_repository::UserRepository;
use crate::application::services::errors::ServiceError;
use crate::application::use_cases::auth::delete_account::DeleteAccount;
use crate::application::use_cases::auth::login::{Login as LoginUc, LoginRequest};
use crate::application::use_cases::auth::me::GetMe;
use crate::application::use_cases::auth::register::{Register as RegisterUc, RegisterRequest};

pub struct AccountService {
    user_repo: Arc<dyn UserRepository>,
    document_repo: Arc<dyn DocumentRepository>,
    plugin_installations: Arc<dyn PluginInstallationRepository>,
    plugin_repo: Arc<dyn PluginRepository>,
    plugin_assets: Arc<dyn PluginAssetStore>,
    git_repo: Arc<dyn GitRepository>,
    git_workspace: Arc<dyn GitWorkspacePort>,
    storage_jobs: Arc<dyn StorageProjectionQueue>,
}

impl AccountService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        document_repo: Arc<dyn DocumentRepository>,
        plugin_installations: Arc<dyn PluginInstallationRepository>,
        plugin_repo: Arc<dyn PluginRepository>,
        plugin_assets: Arc<dyn PluginAssetStore>,
        git_repo: Arc<dyn GitRepository>,
        git_workspace: Arc<dyn GitWorkspacePort>,
        storage_jobs: Arc<dyn StorageProjectionQueue>,
    ) -> Self {
        Self {
            user_repo,
            document_repo,
            plugin_installations,
            plugin_repo,
            plugin_assets,
            git_repo,
            git_workspace,
            storage_jobs,
        }
    }

    pub async fn register(
        &self,
        email: &str,
        name: &str,
        password: &str,
    ) -> Result<UserDto, ServiceError> {
        let uc = RegisterUc {
            repo: self.user_repo.as_ref(),
        };
        uc.execute(&RegisterRequest {
            email: email.to_string(),
            name: name.to_string(),
            password: password.to_string(),
        })
        .await
        .map(|user| UserDto {
            id: user.id,
            email: user.email,
            name: user.name,
        })
        .map_err(|err| {
            tracing::error!(error = ?err, "register_failed");
            ServiceError::Conflict
        })
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
    ) -> Result<Option<UserDto>, ServiceError> {
        let uc = LoginUc {
            repo: self.user_repo.as_ref(),
        };
        uc.execute(&LoginRequest {
            email: email.to_string(),
            password: password.to_string(),
        })
        .await
        .map(|opt| {
            opt.map(|user| UserDto {
                id: user.id,
                email: user.email,
                name: user.name,
            })
        })
        .map_err(ServiceError::from)
    }

    pub async fn get_me(&self, user_id: Uuid) -> Result<Option<UserDto>, ServiceError> {
        let uc = GetMe {
            repo: self.user_repo.as_ref(),
        };
        uc.execute(user_id)
            .await
            .map(|opt| {
                opt.map(|user| UserDto {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                })
            })
            .map_err(ServiceError::from)
    }

    pub async fn delete_account(&self, user_id: Uuid) -> Result<(), ServiceError> {
        let uc = DeleteAccount {
            user_repo: self.user_repo.as_ref(),
            document_repo: self.document_repo.as_ref(),
            plugin_installations: self.plugin_installations.as_ref(),
            plugin_repo: self.plugin_repo.as_ref(),
            plugin_assets: self.plugin_assets.clone(),
            git_repo: self.git_repo.as_ref(),
            git_workspace: self.git_workspace.as_ref(),
            storage_jobs: self.storage_jobs.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }
}
