use std::sync::Arc;

use uuid::Uuid;

use crate::core::dtos::TextDiffResult;
use crate::core::ports::storage::storage_port::StorageResolverPort;
use crate::core::services::errors::ServiceError;
use crate::documents::ports::document_repository::DocumentRepository;
use crate::documents::ports::files::files_repository::FilesRepository;
use crate::git::dtos::{
    GitChangeItem, GitCommitInfo, GitConfigDto, GitPullConflictItemDto, GitPullRequestDto,
    GitPullResolutionDto, GitPullResultDto, GitPullSessionDto, GitRemoteCheckDto, GitStatusDto,
    GitSyncRequestDto, GitSyncResponseDto, GitignoreUpdateDto, UpsertGitConfigInput,
};
use crate::git::ports::git_pull_session_repository::GitPullSessionRepository;
use crate::git::ports::git_repository::GitRepository;
use crate::git::ports::git_workspace::GitWorkspacePort;
use crate::git::ports::gitignore_port::GitignorePort;
use crate::git::use_cases::delete_config::DeleteGitConfig;
use crate::git::use_cases::get_changes::GetChanges;
use crate::git::use_cases::get_commit_diff::GetCommitDiff;
use crate::git::use_cases::get_config::GetGitConfig;
use crate::git::use_cases::get_history::GetHistory;
use crate::git::use_cases::get_status::GetGitStatus;
use crate::git::use_cases::get_working_diff::GetWorkingDiff;
use crate::git::use_cases::gitignore_patterns::{
    AddGitignorePatterns, CheckPathIgnored, GetGitignorePatterns,
};
use crate::git::use_cases::ignore_document::IgnoreDocument;
use crate::git::use_cases::ignore_folder::IgnoreFolder;
use crate::git::use_cases::init_repo::{DeinitRepo, InitRepo};
use crate::git::use_cases::pull::PullRepository;
use crate::git::use_cases::sync_now::SyncNow;
use crate::git::use_cases::upsert_config::UpsertGitConfig;
use domain::git::pull_session::GitPullSessionStatus;
use tracing::warn;

pub mod rebuild;
pub mod rebuild_scheduler;

pub struct GitService {
    repo: Arc<dyn GitRepository>,
    storage: Arc<dyn StorageResolverPort>,
    files: Arc<dyn FilesRepository>,
    docs: Arc<dyn DocumentRepository>,
    gitignore: Arc<dyn GitignorePort>,
    workspace: Arc<dyn GitWorkspacePort>,
    pull_sessions: Arc<dyn GitPullSessionRepository>,
}

pub struct FinalizePullSessionResult {
    pub session: GitPullSessionDto,
    pub git_status: Option<GitStatusDto>,
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

    pub async fn import_repository(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        input: &UpsertGitConfigInput,
    ) -> Result<crate::git::dtos::GitImportOutcome, ServiceError> {
        // Save configuration first
        let _ = self.upsert_config(workspace_id, input).await?;
        let cfg = self
            .repo
            .load_user_git_cfg(workspace_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::BadRequest("git_not_configured"))?;

        self.workspace
            .ensure_repository(workspace_id, &cfg.branch_name)
            .await
            .map_err(ServiceError::from)?;

        self.workspace
            .import_repository(workspace_id, actor_id, &cfg)
            .await
            .map_err(|err| {
                let msg = err.to_string().to_lowercase();
                if msg.contains("git_http_auth_redirect") || msg.contains("too many redirects") {
                    ServiceError::BadRequest("git_auth_redirect")
                } else if msg.contains("git_http_not_found") || msg.contains("status code: 404") {
                    ServiceError::BadRequest("git_repo_not_found")
                } else {
                    ServiceError::from(err)
                }
            })
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
        actor_id: Uuid,
        req: GitPullRequestDto,
    ) -> Result<GitPullResultDto, ServiceError> {
        let uc = PullRepository {
            workspace: self.workspace.as_ref(),
            repo: self.repo.as_ref(),
        };
        let mut dto = uc
            .execute(workspace_id, actor_id, req)
            .await
            .map_err(|err| {
                let msg = err.to_string();
                if msg.contains("pending changes") {
                    ServiceError::BadRequest("workspace_has_pending_changes")
                } else if msg.contains("not initialized") {
                    ServiceError::BadRequest("repository_not_initialized")
                } else if msg.contains("remote not configured") {
                    ServiceError::BadRequest("remote_not_configured")
                } else if msg.contains("git_not_configured") {
                    ServiceError::BadRequest("remote_not_configured")
                } else if msg.contains("custom_text content required") {
                    ServiceError::BadRequest("resolution_content_required")
                } else {
                    ServiceError::from(err)
                }
            })?;

        if let Some(conflicts) = dto.conflicts.take() {
            dto.conflicts = Some(
                self.attach_conflict_documents(workspace_id, conflicts)
                    .await?,
            );
        }

        Ok(dto)
    }

    pub async fn start_pull_session_flow(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
    ) -> Result<GitPullSessionDto, ServiceError> {
        let mut dto = self
            .pull_repository(
                workspace_id,
                actor_id,
                GitPullRequestDto {
                    resolutions: Vec::new(),
                },
            )
            .await?;
        let conflicts = dto.conflicts.clone().unwrap_or_default();
        let session_id = Uuid::new_v4();
        // Align recorded base commit with the current head so stale detection does not flag a
        // successfully merged session.
        if let Some(head) = self.workspace.head_commit(workspace_id).await? {
            dto.base_commit = Some(head);
        }
        let status = if !dto.success && conflicts.is_empty() {
            GitPullSessionStatus::Error
        } else if conflicts.is_empty() {
            GitPullSessionStatus::Merged
        } else {
            GitPullSessionStatus::Pending
        };
        let session = GitPullSessionDto {
            id: session_id,
            workspace_id,
            status,
            conflicts,
            resolutions: Vec::new(),
            message: Some(dto.message.clone()),
            base_commit: dto.base_commit,
            remote_commit: dto.remote_commit,
        };
        self.save_pull_session(session.clone()).await?;
        Ok(session)
    }

    pub async fn resolve_pull_session_flow(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        session_id: Uuid,
        resolutions: Vec<GitPullResolutionDto>,
    ) -> Result<GitPullSessionDto, ServiceError> {
        let existing = self
            .load_pull_session(workspace_id, session_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if self.pull_session_is_stale(workspace_id, &existing).await? {
            let mut stale = existing.clone();
            stale.status = GitPullSessionStatus::Stale;
            stale.message = Some("Pull session is stale".to_string());
            let _ = self.save_pull_session(stale.clone()).await;
            return Ok(stale);
        }

        let dto = self
            .pull_repository(
                workspace_id,
                actor_id,
                GitPullRequestDto {
                    resolutions: resolutions.clone(),
                },
            )
            .await?;
        let conflicts = dto.conflicts.clone().unwrap_or_default();
        let status = if !dto.success && conflicts.is_empty() {
            GitPullSessionStatus::Error
        } else if conflicts.is_empty() {
            GitPullSessionStatus::Merged
        } else {
            GitPullSessionStatus::Resolving
        };
        // When the pull completed (no conflicts), record the latest head as the session base so
        // subsequent finalize calls don't treat the session as stale.
        let mut base_commit = dto.base_commit.clone();
        if conflicts.is_empty() {
            if let Some(head) = self.workspace.head_commit(workspace_id).await? {
                base_commit = Some(head);
            }
        }
        let session = GitPullSessionDto {
            id: session_id,
            workspace_id,
            status,
            conflicts,
            resolutions,
            message: Some(dto.message.clone()),
            base_commit,
            remote_commit: dto.remote_commit,
        };
        self.save_pull_session(session.clone()).await?;
        Ok(session)
    }

    pub async fn finalize_pull_session_flow(
        &self,
        workspace_id: Uuid,
        session_id: Uuid,
    ) -> Result<FinalizePullSessionResult, ServiceError> {
        let existing = self
            .load_pull_session(workspace_id, session_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if existing.status == GitPullSessionStatus::Merged {
            let git_status = self.get_status(workspace_id).await?;
            return Ok(FinalizePullSessionResult {
                session: existing,
                git_status: Some(git_status),
            });
        }
        if existing.status == GitPullSessionStatus::Stale {
            let mut stale = existing.clone();
            if stale.message.is_none() {
                stale.message = Some("Pull session is stale".to_string());
                let _ = self.save_pull_session(stale.clone()).await;
            }
            return Ok(FinalizePullSessionResult {
                session: stale,
                git_status: None,
            });
        }
        if existing.status == GitPullSessionStatus::Error {
            return Ok(FinalizePullSessionResult {
                session: existing,
                git_status: None,
            });
        }
        if existing.status.is_in_progress()
            && self.pull_session_is_stale(workspace_id, &existing).await?
        {
            let mut stale = existing.clone();
            stale.status = GitPullSessionStatus::Stale;
            if stale.message.is_none() {
                stale.message = Some("Pull session is stale".to_string());
            }
            let _ = self.save_pull_session(stale.clone()).await;
            return Ok(FinalizePullSessionResult {
                session: stale,
                git_status: None,
            });
        }
        if !existing.conflicts.is_empty() {
            return Ok(FinalizePullSessionResult {
                session: existing,
                git_status: None,
            });
        }
        let git_status = self.get_status(workspace_id).await?;
        let merged = GitPullSessionDto {
            id: session_id,
            workspace_id,
            status: GitPullSessionStatus::Merged,
            conflicts: Vec::new(),
            resolutions: existing.resolutions.clone(),
            message: Some("merge completed".to_string()),
            base_commit: existing.base_commit.clone(),
            remote_commit: existing.remote_commit.clone(),
        };
        let _ = self.save_pull_session(merged.clone()).await;
        Ok(FinalizePullSessionResult {
            session: merged,
            git_status: Some(git_status),
        })
    }

    pub async fn load_pull_session_with_stale_check(
        &self,
        workspace_id: Uuid,
        id: Uuid,
    ) -> Result<Option<GitPullSessionDto>, ServiceError> {
        let mut session = match self.load_pull_session(workspace_id, id).await? {
            Some(s) => s,
            None => return Ok(None),
        };
        if session.status.is_in_progress()
            && self.pull_session_is_stale(workspace_id, &session).await?
        {
            session.status = GitPullSessionStatus::Stale;
            session.message = Some("Pull session is stale".to_string());
            let _ = self.save_pull_session(session.clone()).await;
        }
        Ok(Some(session))
    }

    async fn attach_conflict_documents(
        &self,
        workspace_id: Uuid,
        conflicts: Vec<GitPullConflictItemDto>,
    ) -> Result<Vec<GitPullConflictItemDto>, ServiceError> {
        let mut out = Vec::with_capacity(conflicts.len());
        let docs = self
            .docs
            .list_workspace_documents(workspace_id)
            .await
            .map_err(ServiceError::from)?;

        let normalize = |path: &str| {
            path.trim_start_matches("./")
                .trim_start_matches('/')
                .to_string()
        };

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
                let desired = normalize(doc.desired_path.as_str());
                if !desired.is_empty() {
                    paths.push(desired);
                }

                if paths.iter().any(|p| {
                    candidate == *p
                        || candidate.ends_with(&format!("/{p}"))
                        || p.ends_with(&candidate)
                }) {
                    matched = Some(doc.id);
                    break;
                }
            }

            conflict.document_id = matched;
            if let Some(doc_id) = matched {
                if let Some(doc) = docs.iter().find(|d| d.id == doc_id) {
                    conflict.path = doc.desired_path.as_str().to_string();
                }
            }
            out.push(conflict);
        }

        Ok(out)
    }

    pub async fn save_pull_session(&self, session: GitPullSessionDto) -> Result<(), ServiceError> {
        self.pull_sessions
            .upsert(session)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn load_pull_session(
        &self,
        workspace_id: Uuid,
        id: Uuid,
    ) -> Result<Option<GitPullSessionDto>, ServiceError> {
        self.pull_sessions
            .get(workspace_id, id)
            .await
            .map_err(ServiceError::from)
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
            return Err(ServiceError::BadRequest("remote_not_configured"));
        };

        if let Some(saved_base) = session.base_commit.as_ref() {
            let current_head = self
                .workspace
                .head_commit(workspace_id)
                .await
                .map_err(ServiceError::from)?;
            match current_head {
                Some(head) if saved_base == &head => {}
                Some(head)
                    if session
                        .remote_commit
                        .as_ref()
                        .is_some_and(|remote| remote == &head) => {}
                Some(_) | None => return Ok(true),
            }
        }

        if let Some(saved_remote) = session.remote_commit.as_ref() {
            match self.workspace.remote_head(workspace_id, &cfg).await {
                Ok(Some(current_remote)) => {
                    if saved_remote != &current_remote {
                        return Ok(true);
                    }
                }
                Ok(None) => return Ok(true),
                Err(err) => {
                    let msg = err.to_string();
                    let mapped = if msg.contains("not initialized") {
                        ServiceError::BadRequest("repository_not_initialized")
                    } else if msg.contains("remote not configured") {
                        ServiceError::BadRequest("remote_not_configured")
                    } else {
                        ServiceError::from(err)
                    };
                    warn!(
                        workspace_id = %workspace_id,
                        error = %msg,
                        "git_pull_remote_head_unavailable"
                    );
                    return Err(mapped);
                }
            }
        }

        Ok(false)
    }
}
