use std::sync::Arc;

use uuid::Uuid;

use crate::contracts::auth::UserDto;
use crate::ports::document_repository::DocumentRepository;
use crate::ports::files_repository::FilesRepository;
use crate::ports::git_repository::GitRepository;
use crate::ports::git_workspace::GitWorkspacePort;
use crate::ports::plugin_asset_store::PluginAssetStore;
use crate::ports::plugin_installation_repository::PluginInstallationRepository;
use crate::ports::plugin_repository::PluginRepository;
use crate::ports::storage_projection_queue::StorageProjectionQueue;
use crate::ports::user_repository::UserRepository;
use crate::services::auth::external::ExternalAuthIdentity;
use crate::services::errors::ServiceError;
use crate::services::workspaces::WorkspaceService;
use crate::use_cases::auth::delete_account::DeleteAccount;
use crate::use_cases::auth::login::{Login as LoginUc, LoginRequest};
use crate::use_cases::auth::me::GetMe;
use crate::use_cases::auth::register::{Register as RegisterUc, RegisterRequest};

pub struct AccountService {
    user_repo: Arc<dyn UserRepository>,
    document_repo: Arc<dyn DocumentRepository>,
    files_repo: Arc<dyn FilesRepository>,
    plugin_installations: Arc<dyn PluginInstallationRepository>,
    plugin_repo: Arc<dyn PluginRepository>,
    plugin_assets: Arc<dyn PluginAssetStore>,
    git_repo: Arc<dyn GitRepository>,
    git_workspace: Arc<dyn GitWorkspacePort>,
    storage_jobs: Arc<dyn StorageProjectionQueue>,
    workspace_service: Arc<WorkspaceService>,
}

impl AccountService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        document_repo: Arc<dyn DocumentRepository>,
        files_repo: Arc<dyn FilesRepository>,
        plugin_installations: Arc<dyn PluginInstallationRepository>,
        plugin_repo: Arc<dyn PluginRepository>,
        plugin_assets: Arc<dyn PluginAssetStore>,
        git_repo: Arc<dyn GitRepository>,
        git_workspace: Arc<dyn GitWorkspacePort>,
        storage_jobs: Arc<dyn StorageProjectionQueue>,
        workspace_service: Arc<WorkspaceService>,
    ) -> Self {
        Self {
            user_repo,
            document_repo,
            files_repo,
            plugin_installations,
            plugin_repo,
            plugin_assets,
            git_repo,
            git_workspace,
            storage_jobs,
            workspace_service,
        }
    }

    pub async fn register(
        &self,
        email: &str,
        name: &str,
        password: &str,
    ) -> Result<UserDto, ServiceError> {
        let user_id = Uuid::new_v4();
        // personal workspace shares the same UUID as the user; provision it before inserting user row
        self.workspace_service
            .create_personal_workspace_shell(user_id, name)
            .await?;
        let uc = RegisterUc {
            repo: self.user_repo.as_ref(),
        };
        let register_request = RegisterRequest {
            id: user_id,
            email: email.to_string(),
            name: name.to_string(),
            password: password.to_string(),
            default_workspace_id: user_id,
        };
        let user = match uc.execute(&register_request).await {
            Ok(user) => user,
            Err(err) => {
                if let Err(err) = self.workspace_service.delete_workspace(user_id).await {
                    tracing::warn!(error = ?err, user_id = %user_id, "workspace_cleanup_failed");
                }
                tracing::error!(error = ?err, "register_failed");
                return Err(ServiceError::Conflict);
            }
        };

        self.workspace_service
            .ensure_owner_membership(user_id, user_id)
            .await?;

        Ok(UserDto {
            id: user.id,
            email: user.email,
            name: user.name,
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
            files_repo: self.files_repo.as_ref(),
            plugin_installations: self.plugin_installations.as_ref(),
            plugin_repo: self.plugin_repo.as_ref(),
            plugin_assets: self.plugin_assets.clone(),
            git_repo: self.git_repo.as_ref(),
            git_workspace: self.git_workspace.as_ref(),
            storage_jobs: self.storage_jobs.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }

    pub async fn sign_in_with_external(
        &self,
        identity: ExternalAuthIdentity,
    ) -> Result<UserDto, ServiceError> {
        if !identity.email_verified {
            return Err(ServiceError::Unauthorized);
        }
        self.handle_external_identity(identity)
            .await
            .map_err(ServiceError::from)
    }

    async fn handle_external_identity(
        &self,
        identity: ExternalAuthIdentity,
    ) -> Result<UserDto, ServiceError> {
        let provider = identity.provider.as_str();
        let subject = identity.subject.clone();
        if let Some(existing) = self
            .user_repo
            .find_by_external_identity(provider, &subject)
            .await
            .map_err(ServiceError::from)?
        {
            return Ok(UserDto {
                id: existing.id,
                email: existing.email,
                name: existing.name,
            });
        }

        let email = identity
            .email
            .clone()
            .ok_or(ServiceError::BadRequest("email_required"))?;

        if let Some(existing) = self
            .user_repo
            .find_by_email(&email)
            .await
            .map_err(ServiceError::from)?
        {
            self.user_repo
                .link_external_identity(existing.id, provider, &subject)
                .await
                .map_err(ServiceError::from)?;
            return Ok(UserDto {
                id: existing.id,
                email: existing.email,
                name: existing.name,
            });
        }

        let user = self.create_external_user(&email, &identity).await?;
        self.user_repo
            .link_external_identity(user.id, provider, &subject)
            .await
            .map_err(ServiceError::from)?;
        Ok(user)
    }

    async fn create_external_user(
        &self,
        email: &str,
        identity: &ExternalAuthIdentity,
    ) -> Result<UserDto, ServiceError> {
        let trimmed_name = identity
            .name
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                email
                    .split('@')
                    .next()
                    .unwrap_or("User")
                    .chars()
                    .take(64)
                    .collect()
            });
        let user_id = Uuid::new_v4();
        self.workspace_service
            .create_personal_workspace_shell(user_id, &trimmed_name)
            .await?;

        let create_result = self
            .user_repo
            .create_user(user_id, email, &trimmed_name, None, user_id)
            .await;

        let user = match create_result {
            Ok(user) => user,
            Err(err) => {
                if let Err(cleanup_err) = self.workspace_service.delete_workspace(user_id).await {
                    tracing::warn!(
                        error = ?cleanup_err,
                        user_id = %user_id,
                        "workspace_cleanup_failed"
                    );
                }
                tracing::error!(error = ?err, "external_register_failed");
                return Err(ServiceError::Conflict);
            }
        };

        self.workspace_service
            .ensure_owner_membership(user_id, user_id)
            .await?;

        Ok(UserDto {
            id: user.id,
            email: user.email,
            name: user.name,
        })
    }
}
