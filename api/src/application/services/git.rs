use std::sync::Arc;

use uuid::Uuid;

use crate::application::dto::diff::TextDiffResult;
use crate::application::dto::git::{
    GitChangeItem, GitCommitInfo, GitConfigDto, GitPullConflictItemDto, GitRemoteCheckDto,
    GitStatusDto, GitSyncRequestDto, GitSyncResponseDto, GitignoreUpdateDto, GitPullRequestDto,
    GitPullResultDto, GitPullSessionDto, UpsertGitConfigInput,
};
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::git_pull_session_repository::GitPullSessionRepository;
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
use crate::application::use_cases::git::pull::PullRepository;
use crate::application::use_cases::git::sync_now::SyncNow;
use crate::application::use_cases::git::upsert_config::UpsertGitConfig;

pub struct GitService {
    repo: Arc<dyn GitRepository>,
    storage: Arc<dyn StorageResolverPort>,
    files: Arc<dyn FilesRepository>,
    docs: Arc<dyn DocumentRepository>,
    gitignore: Arc<dyn GitignorePort>,
    workspace: Arc<dyn GitWorkspacePort>,
    pull_sessions: Arc<dyn GitPullSessionRepository>,
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
        pull_sessions: Arc<dyn GitPullSessionRepository>,
    ) -> Self {
        Self {
            repo,
            storage,
            files,
            docs,
            gitignore,
            workspace,
            pull_sessions,
        }
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

    pub async fn check_remote(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<GitRemoteCheckDto>, ServiceError> {
        let cfg = self
            .repo
            .load_user_git_cfg(workspace_id)
            .await
            .map_err(ServiceError::from)?;
        let Some(cfg) = cfg else {
            return Ok(None);
        };
        let res = self
            .workspace
            .check_remote(workspace_id, &cfg)
            .await
            .map_err(ServiceError::from)?;
        Ok(Some(res))
    }

    pub async fn upsert_config(
        &self,
        workspace_id: Uuid,
        input: &UpsertGitConfigInput,
    ) -> Result<GitConfigDto, ServiceError> {
        let uc = UpsertGitConfig {
            repo: self.repo.as_ref(),
            storage: self.storage.as_ref(),
            gitignore: self.gitignore.as_ref(),
            workspace: self.workspace.as_ref(),
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

    pub async fn get_status(&self, workspace_id: Uuid) -> Result<GitStatusDto, ServiceError> {
        let uc = GetGitStatus {
            repo: self.repo.as_ref(),
            workspace: self.workspace.as_ref(),
        };
        uc.execute(workspace_id).await.map_err(ServiceError::from)
    }

    pub async fn sync_now(
        &self,
        workspace_id: Uuid,
        payload: GitSyncRequestDto,
    ) -> Result<GitSyncResponseDto, ServiceError> {
        let uc = SyncNow {
            workspace: self.workspace.as_ref(),
            repo: self.repo.as_ref(),
        };
        uc.execute(workspace_id, payload).await.map_err(|err| {
            let msg_lower = err.to_string().to_lowercase();
            if msg_lower.contains("git_http_auth_redirect")
                || msg_lower.contains("too many redirects")
                || msg_lower.contains("http (34)")
            {
                ServiceError::BadRequest("git_auth_redirect")
            } else if msg_lower.contains("git_http_not_found")
                || msg_lower.contains("status code: 404")
            {
                ServiceError::BadRequest("git_repo_not_found")
            } else if msg_lower.contains("notfastforward")
                || msg_lower.contains("not fast forward")
                || msg_lower.contains("non-fast-forward")
                || msg_lower.contains("non fast forward")
                || msg_lower.contains("cannot push because a reference")
                || msg_lower.contains("failed to push some refs")
                || msg_lower.contains("updates were rejected")
                || msg_lower.contains("rejected")
            {
                ServiceError::Conflict
            } else {
                ServiceError::from(err)
            }
        })
    }

    pub async fn get_changes(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<GitChangeItem>, ServiceError> {
        let uc = GetChanges {
            workspace: self.workspace.as_ref(),
        };
        uc.execute(workspace_id).await.map_err(ServiceError::from)
    }

    pub async fn get_history(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<GitCommitInfo>, ServiceError> {
        let uc = GetHistory {
            workspace: self.workspace.as_ref(),
        };
        uc.execute(workspace_id).await.map_err(ServiceError::from)
    }

    pub async fn get_working_diff(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<TextDiffResult>, ServiceError> {
        let uc = GetWorkingDiff {
            workspace: self.workspace.as_ref(),
        };
        uc.execute(workspace_id).await.map_err(ServiceError::from)
    }

    pub async fn get_commit_diff(
        &self,
        workspace_id: Uuid,
        from: &str,
        to: &str,
    ) -> Result<Vec<TextDiffResult>, ServiceError> {
        let uc = GetCommitDiff {
            workspace: self.workspace.as_ref(),
        };
        uc.execute(workspace_id, from.to_string(), to.to_string())
            .await
            .map_err(ServiceError::from)
    }

    pub async fn init_repository(&self, workspace_id: Uuid) -> Result<(), ServiceError> {
        let uc = InitRepo {
            repo: self.repo.as_ref(),
            storage: self.storage.as_ref(),
            gitignore: self.gitignore.as_ref(),
            workspace: self.workspace.as_ref(),
        };
        uc.execute(workspace_id).await.map_err(ServiceError::from)
    }

    pub async fn deinit_repository(&self, workspace_id: Uuid) -> Result<(), ServiceError> {
        let uc = DeinitRepo {
            workspace: self.workspace.as_ref(),
        };
        uc.execute(workspace_id).await.map_err(ServiceError::from)?;
        self.repo
            .delete_sync_logs(workspace_id)
            .await
            .map_err(ServiceError::from)?;
        self.repo
            .delete_repository_state(workspace_id)
            .await
            .map_err(ServiceError::from)?;
        self.repo
            .delete_config(workspace_id)
            .await
            .map(|_| ())
            .map_err(ServiceError::from)
    }

    pub async fn ignore_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> Result<GitignoreUpdateDto, ServiceError> {
        let uc = IgnoreDocument {
            storage: self.storage.as_ref(),
            files: self.files.as_ref(),
            docs: self.docs.as_ref(),
            gitignore: self.gitignore.as_ref(),
            workspace: self.workspace.as_ref(),
        };
        uc.execute(workspace_id, doc_id)
            .await
            .map(|res| GitignoreUpdateDto {
                added: res.added,
                patterns: res.patterns,
            })
            .map_err(ServiceError::from)
    }

    pub async fn ignore_folder(
        &self,
        workspace_id: Uuid,
        folder_id: Uuid,
    ) -> Result<GitignoreUpdateDto, ServiceError> {
        let uc = IgnoreFolder {
            storage: self.storage.as_ref(),
            files: self.files.as_ref(),
            docs: self.docs.as_ref(),
            gitignore: self.gitignore.as_ref(),
            workspace: self.workspace.as_ref(),
        };
        uc.execute(workspace_id, folder_id)
            .await
            .map(|res| GitignoreUpdateDto {
                added: res.added,
                patterns: res.patterns,
            })
            .map_err(ServiceError::from)
    }

    pub async fn add_gitignore_patterns(
        &self,
        workspace_id: Uuid,
        patterns: Vec<String>,
    ) -> Result<i64, ServiceError> {
        let uc = AddGitignorePatterns {
            storage: self.storage.as_ref(),
            gitignore: self.gitignore.as_ref(),
            workspace: self.workspace.as_ref(),
        };
        uc.execute(workspace_id, patterns)
            .await
            .map(|count| count as i64)
            .map_err(ServiceError::from)
    }

    pub async fn get_gitignore_patterns(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<String>, ServiceError> {
        let uc = GetGitignorePatterns {
            storage: self.storage.as_ref(),
            gitignore: self.gitignore.as_ref(),
        };
        uc.execute(workspace_id).await.map_err(ServiceError::from)
    }

    pub async fn check_path_ignored(
        &self,
        workspace_id: Uuid,
        path: &str,
    ) -> Result<bool, ServiceError> {
        let uc = CheckPathIgnored {
            gitignore: self.gitignore.as_ref(),
            storage: self.storage.as_ref(),
        };
        uc.execute(workspace_id, path)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn pull_repository(
        &self,
        workspace_id: Uuid,
        req: GitPullRequestDto,
    ) -> Result<GitPullResultDto, ServiceError> {
        let uc = PullRepository {
            workspace: self.workspace.as_ref(),
            repo: self.repo.as_ref(),
        };
        let mut dto = uc.execute(workspace_id, req).await.map_err(|err| {
            let msg = err.to_string();
            if msg.contains("pending changes") {
                ServiceError::BadRequest("workspace_has_pending_changes")
            } else if msg.contains("not initialized") {
                ServiceError::BadRequest("repository_not_initialized")
            } else if msg.contains("remote not configured") {
                ServiceError::BadRequest("remote_not_configured")
            } else {
                ServiceError::from(err)
            }
        })?;

        if let Some(conflicts) = dto.conflicts.take() {
            dto.conflicts = Some(self.attach_conflict_documents(workspace_id, conflicts).await?);
        }

        Ok(dto)
    }

    async fn attach_conflict_documents(
        &self,
        workspace_id: Uuid,
        conflicts: Vec<GitPullConflictItemDto>,
    ) -> Result<Vec<GitPullConflictItemDto>, ServiceError> {
        let mut out = Vec::with_capacity(conflicts.len());
        let docs = self.docs.list_workspace_documents(workspace_id).await.map_err(ServiceError::from)?;

        let normalize = |path: &str| path.trim_start_matches("./").trim_start_matches('/').to_string();

        for mut conflict in conflicts {
            if conflict.document_id.is_some() {
                out.push(conflict);
                continue;
            }
            let candidate = normalize(&conflict.path);

            let mut matched = None;
            for doc in docs.iter() {
                let mut paths: Vec<String> = Vec::new();
                if let Some(p) = doc.path.as_ref() {
                    let norm = normalize(p);
                    if !norm.is_empty() {
                        paths.push(norm);
                    }
                }
                let desired = normalize(&doc.desired_path);
                if !desired.is_empty() {
                    paths.push(desired);
                }

                if paths.iter().any(|p| candidate == *p || candidate.ends_with(&format!("/{p}")) || p.ends_with(&candidate)) {
                    matched = Some(doc.id);
                    break;
                }
            }

            conflict.document_id = matched;
            if let Some(doc_id) = matched {
                if let Some(doc) = docs.iter().find(|d| d.id == doc_id) {
                    conflict.path = doc.desired_path.clone();
                }
            }
            out.push(conflict);
        }

        Ok(out)
    }

    pub async fn start_pull_session(
        &self,
        workspace_id: Uuid,
    ) -> Result<GitPullResultDto, ServiceError> {
        self
            .pull_repository(workspace_id, GitPullRequestDto { resolutions: Vec::new() })
            .await
    }

    pub async fn save_pull_session(&self, session: GitPullSessionDto) -> Result<(), ServiceError> {
        self.pull_sessions.upsert(session).await.map_err(ServiceError::from)
    }

    pub async fn load_pull_session(
        &self,
        workspace_id: Uuid,
        id: Uuid,
    ) -> Result<Option<GitPullSessionDto>, ServiceError> {
        self.pull_sessions.get(workspace_id, id).await.map_err(ServiceError::from)
    }

    pub async fn pull_session_is_stale(
        &self,
        workspace_id: Uuid,
        session: &GitPullSessionDto,
    ) -> Result<bool, ServiceError> {
        let cfg = self
            .repo
            .load_user_git_cfg(workspace_id)
            .await
            .map_err(ServiceError::from)?;
        let Some(cfg) = cfg else {
            return Ok(true);
        };

        if let Some(saved_base) = session.base_commit.as_ref() {
            if let Some(current_head) = self
                .workspace
                .head_commit(workspace_id)
                .await
                .map_err(ServiceError::from)?
            {
                // Only mark stale if the recorded base commit diverges from the latest committed head.
                if saved_base != &current_head {
                    return Ok(true);
                }
            }
        }

        if let Some(saved_remote) = session.remote_commit.as_ref() {
            if let Some(current_remote) = self
                .workspace
                .remote_head(workspace_id, &cfg)
                .await
                .map_err(ServiceError::from)?
            {
                if saved_remote != &current_remote {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}
