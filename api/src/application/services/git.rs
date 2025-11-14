use std::sync::Arc;

use uuid::Uuid;

use crate::application::dto::diff::TextDiffResult;
use crate::application::dto::git::{
    GitChangeItem, GitCommitInfo, GitConfigDto, GitStatusDto, GitSyncRequestDto,
    GitSyncResponseDto, GitignoreUpdateDto, UpsertGitConfigInput,
};
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::gitignore_port::GitignorePort;
use crate::application::ports::storage_port::StorageResolverPort;
use crate::application::services::errors::ServiceError;
use crate::application::use_cases::git::delete_config::DeleteGitConfig;
use crate::application::use_cases::git::get_changes::GetChanges;
use crate::application::use_cases::git::get_commit_diff::GetCommitDiff;
use crate::application::use_cases::git::get_config::GetGitConfig;
use crate::application::use_cases::git::get_history::GetHistory;
use crate::application::use_cases::git::get_status::GetGitStatus;
use crate::application::use_cases::git::get_working_diff::GetWorkingDiff;
use crate::application::use_cases::git::gitignore_patterns::{
    AddGitignorePatterns, CheckPathIgnored, GetGitignorePatterns,
};
use crate::application::use_cases::git::ignore_document::IgnoreDocument;
use crate::application::use_cases::git::ignore_folder::IgnoreFolder;
use crate::application::use_cases::git::init_repo::{DeinitRepo, InitRepo};
use crate::application::use_cases::git::sync_now::SyncNow;
use crate::application::use_cases::git::upsert_config::UpsertGitConfig;

pub struct GitService {
    repo: Arc<dyn GitRepository>,
    storage: Arc<dyn StorageResolverPort>,
    files: Arc<dyn FilesRepository>,
    docs: Arc<dyn DocumentRepository>,
    gitignore: Arc<dyn GitignorePort>,
    workspace: Arc<dyn GitWorkspacePort>,
}

impl GitService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repo: Arc<dyn GitRepository>,
        storage: Arc<dyn StorageResolverPort>,
        files: Arc<dyn FilesRepository>,
        docs: Arc<dyn DocumentRepository>,
        gitignore: Arc<dyn GitignorePort>,
        workspace: Arc<dyn GitWorkspacePort>,
    ) -> Self {
        Self {
            repo,
            storage,
            files,
            docs,
            gitignore,
            workspace,
        }
    }

    pub async fn get_config(&self, user_id: Uuid) -> Result<Option<GitConfigDto>, ServiceError> {
        let uc = GetGitConfig {
            repo: self.repo.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }

    pub async fn upsert_config(
        &self,
        user_id: Uuid,
        input: &UpsertGitConfigInput,
    ) -> Result<GitConfigDto, ServiceError> {
        let uc = UpsertGitConfig {
            repo: self.repo.as_ref(),
            storage: self.storage.as_ref(),
            gitignore: self.gitignore.as_ref(),
            workspace: self.workspace.as_ref(),
        };
        uc.execute(user_id, input).await.map_err(ServiceError::from)
    }

    pub async fn delete_config(&self, user_id: Uuid) -> Result<(), ServiceError> {
        let uc = DeleteGitConfig {
            repo: self.repo.as_ref(),
        };
        uc.execute(user_id)
            .await
            .map(|_| ())
            .map_err(ServiceError::from)
    }

    pub async fn get_status(&self, user_id: Uuid) -> Result<GitStatusDto, ServiceError> {
        let uc = GetGitStatus {
            repo: self.repo.as_ref(),
            workspace: self.workspace.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }

    pub async fn sync_now(
        &self,
        user_id: Uuid,
        payload: GitSyncRequestDto,
    ) -> Result<GitSyncResponseDto, ServiceError> {
        let uc = SyncNow {
            workspace: self.workspace.as_ref(),
            repo: self.repo.as_ref(),
        };
        uc.execute(user_id, payload)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn get_changes(&self, user_id: Uuid) -> Result<Vec<GitChangeItem>, ServiceError> {
        let uc = GetChanges {
            workspace: self.workspace.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }

    pub async fn get_history(&self, user_id: Uuid) -> Result<Vec<GitCommitInfo>, ServiceError> {
        let uc = GetHistory {
            workspace: self.workspace.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }

    pub async fn get_working_diff(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<TextDiffResult>, ServiceError> {
        let uc = GetWorkingDiff {
            workspace: self.workspace.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }

    pub async fn get_commit_diff(
        &self,
        user_id: Uuid,
        from: &str,
        to: &str,
    ) -> Result<Vec<TextDiffResult>, ServiceError> {
        let uc = GetCommitDiff {
            workspace: self.workspace.as_ref(),
        };
        uc.execute(user_id, from.to_string(), to.to_string())
            .await
            .map_err(ServiceError::from)
    }

    pub async fn init_repository(&self, user_id: Uuid) -> Result<(), ServiceError> {
        let uc = InitRepo {
            repo: self.repo.as_ref(),
            storage: self.storage.as_ref(),
            gitignore: self.gitignore.as_ref(),
            workspace: self.workspace.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }

    pub async fn deinit_repository(&self, user_id: Uuid) -> Result<(), ServiceError> {
        let uc = DeinitRepo {
            workspace: self.workspace.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }

    pub async fn ignore_document(
        &self,
        user_id: Uuid,
        doc_id: Uuid,
    ) -> Result<GitignoreUpdateDto, ServiceError> {
        let uc = IgnoreDocument {
            storage: self.storage.as_ref(),
            files: self.files.as_ref(),
            docs: self.docs.as_ref(),
            gitignore: self.gitignore.as_ref(),
            workspace: self.workspace.as_ref(),
        };
        uc.execute(user_id, doc_id)
            .await
            .map(|res| GitignoreUpdateDto {
                added: res.added,
                patterns: res.patterns,
            })
            .map_err(ServiceError::from)
    }

    pub async fn ignore_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
    ) -> Result<GitignoreUpdateDto, ServiceError> {
        let uc = IgnoreFolder {
            storage: self.storage.as_ref(),
            files: self.files.as_ref(),
            docs: self.docs.as_ref(),
            gitignore: self.gitignore.as_ref(),
            workspace: self.workspace.as_ref(),
        };
        uc.execute(user_id, folder_id)
            .await
            .map(|res| GitignoreUpdateDto {
                added: res.added,
                patterns: res.patterns,
            })
            .map_err(ServiceError::from)
    }

    pub async fn add_gitignore_patterns(
        &self,
        user_id: Uuid,
        patterns: Vec<String>,
    ) -> Result<i64, ServiceError> {
        let uc = AddGitignorePatterns {
            storage: self.storage.as_ref(),
            gitignore: self.gitignore.as_ref(),
            workspace: self.workspace.as_ref(),
        };
        uc.execute(user_id, patterns)
            .await
            .map(|count| count as i64)
            .map_err(ServiceError::from)
    }

    pub async fn get_gitignore_patterns(&self, user_id: Uuid) -> Result<Vec<String>, ServiceError> {
        let uc = GetGitignorePatterns {
            storage: self.storage.as_ref(),
            gitignore: self.gitignore.as_ref(),
        };
        uc.execute(user_id).await.map_err(ServiceError::from)
    }

    pub async fn check_path_ignored(
        &self,
        user_id: Uuid,
        path: &str,
    ) -> Result<bool, ServiceError> {
        let uc = CheckPathIgnored {
            gitignore: self.gitignore.as_ref(),
            storage: self.storage.as_ref(),
        };
        uc.execute(user_id, path).await.map_err(ServiceError::from)
    }
}
