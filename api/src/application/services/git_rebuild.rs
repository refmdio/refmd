use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};
#[cfg(test)]
use uuid::Uuid;

use crate::application::dto::git::GitSyncRequestDto;
use crate::application::ports::git_rebuild_job_queue::{GitRebuildJob, GitRebuildJobQueue};
use crate::application::ports::git_repository::GitRepository;
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::services::metrics::MetricsRegistry;
use crate::application::services::workspaces::permissions::{
    PERM_GIT_SYNC, permission_set_from_snapshot,
};
use crate::application::use_cases::git::helpers::needs_force_retry;

pub struct GitRebuildService {
    jobs: Arc<dyn GitRebuildJobQueue>,
    workspace: Arc<dyn GitWorkspacePort>,
    git_repo: Arc<dyn GitRepository>,
    metrics: Arc<MetricsRegistry>,
    idle_backoff: Duration,
    lock_timeout_secs: i64,
    max_attempts: i32,
}

impl GitRebuildService {
    pub fn new(
        jobs: Arc<dyn GitRebuildJobQueue>,
        workspace: Arc<dyn GitWorkspacePort>,
        git_repo: Arc<dyn GitRepository>,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        Self {
            jobs,
            workspace,
            git_repo,
            metrics,
            idle_backoff: Duration::from_secs(1),
            lock_timeout_secs: 30,
            max_attempts: 5,
        }
    }

    pub fn with_idle_backoff(mut self, backoff: Duration) -> Self {
        self.idle_backoff = backoff;
        self
    }

    pub fn with_lock_timeout(mut self, secs: i64) -> Self {
        self.lock_timeout_secs = secs.max(1);
        self
    }

    pub fn with_max_attempts(mut self, attempts: i32) -> Self {
        self.max_attempts = attempts.max(1);
        self
    }

    pub async fn run(self: Arc<Self>) {
        loop {
            match self.jobs.fetch_next(self.lock_timeout_secs).await {
                Ok(Some(job)) => {
                    if let Err(err) = self.process_job(&job).await {
                        error!(error = ?err, job_id = job.id, "git_rebuild_job_failed");
                    }
                }
                Ok(None) => tokio::time::sleep(self.idle_backoff).await,
                Err(err) => {
                    error!(error = ?err, "git_rebuild_fetch_failed");
                    tokio::time::sleep(self.idle_backoff).await;
                }
            }
        }
    }

    async fn process_job(&self, job: &GitRebuildJob) -> anyhow::Result<()> {
        let permissions = permission_set_from_snapshot(&job.permission_snapshot);
        if !permissions.allows(PERM_GIT_SYNC) {
            warn!(
                workspace_id = %job.workspace_id,
                "git_rebuild_missing_permission"
            );
            self.jobs.complete(job.id).await?;
            return Ok(());
        }
        let status = self.workspace.status(job.workspace_id).await?;
        if !status.repository_initialized {
            self.jobs.complete(job.id).await?;
            info!(
                workspace_id = %job.workspace_id,
                "git_rebuild_job_skipped_for_uninitialized_repo"
            );
            return Ok(());
        }
        let cfg = self.git_repo.load_user_git_cfg(job.workspace_id).await?;
        let mut req = GitSyncRequestDto {
            message: Some("Automated Git rebuild".to_string()),
            force: Some(false),
            full_scan: Some(true),
            skip_push: Some(true),
        };
        let outcome = match self
            .workspace
            .sync(job.workspace_id, &req, cfg.as_ref())
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                if !req.force.unwrap_or(false) && needs_force_retry(&err) {
                    warn!(
                        workspace_id = %job.workspace_id,
                        "git_rebuild_retrying_with_force"
                    );
                    req.force = Some(true);
                    match self
                        .workspace
                        .sync(job.workspace_id, &req, cfg.as_ref())
                        .await
                    {
                        Ok(outcome) => outcome,
                        Err(err) => return self.on_job_error(job, err).await,
                    }
                } else {
                    return self.on_job_error(job, err).await;
                }
            }
        };

        self.jobs.complete(job.id).await?;
        self.metrics.inc_git_rebuild_success();
        info!(
            workspace_id = %job.workspace_id,
            files = outcome.files_changed,
            "git_rebuild_job_completed"
        );
        if let Err(err) = self
            .git_repo
            .log_sync_operation(
                job.workspace_id,
                "rebuild",
                "success",
                Some(&outcome.message),
                outcome.commit_hash.as_deref(),
            )
            .await
        {
            warn!(
                error = ?err,
                workspace_id = %job.workspace_id,
                "git_rebuild_log_failed"
            );
        }
        Ok(())
    }

    async fn on_job_error(&self, job: &GitRebuildJob, err: anyhow::Error) -> anyhow::Result<()> {
        let msg = format!("{err:#}");
        if job.attempts >= self.max_attempts {
            self.jobs.complete(job.id).await?;
            self.metrics.inc_git_rebuild_failure();
            warn!(
                error = ?err,
                workspace_id = %job.workspace_id,
                attempts = job.attempts,
                "git_rebuild_job_gave_up"
            );
            if let Err(log_err) = self
                .git_repo
                .log_sync_operation(job.workspace_id, "rebuild", "error", Some(&msg), None)
                .await
            {
                warn!(
                    error = ?log_err,
                    workspace_id = %job.workspace_id,
                    "git_rebuild_log_failed"
                );
            }
        } else {
            self.jobs.fail(job.id, &msg).await?;
            self.metrics.inc_git_rebuild_retry();
            warn!(
                error = ?err,
                workspace_id = %job.workspace_id,
                "git_rebuild_job_retrying"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct RecordingWorkspace {
        outcomes: Mutex<Vec<GitSyncRequestDto>>,
        failures: Mutex<VecDeque<anyhow::Error>>,
    }

    impl RecordingWorkspace {
        fn new() -> Self {
            Self {
                outcomes: Mutex::new(Vec::new()),
                failures: Mutex::new(VecDeque::new()),
            }
        }

        fn fail_with(&self, err: anyhow::Error) {
            self.failures.lock().unwrap().push_back(err);
        }

        fn requests(&self) -> Vec<GitSyncRequestDto> {
            self.outcomes.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl GitWorkspacePort for RecordingWorkspace {
        async fn ensure_repository(
            &self,
            _workspace_id: Uuid,
            _default_branch: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn remove_repository(&self, _workspace_id: Uuid) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn status(
            &self,
            _workspace_id: Uuid,
        ) -> anyhow::Result<crate::application::dto::git::GitWorkspaceStatus> {
            Ok(crate::application::dto::git::GitWorkspaceStatus {
                repository_initialized: true,
                current_branch: Some("main".into()),
                uncommitted_changes: 0,
                untracked_files: 0,
            })
        }

        async fn list_changes(
            &self,
            _workspace_id: Uuid,
        ) -> anyhow::Result<Vec<crate::application::dto::git::GitChangeItem>> {
            unimplemented!()
        }

        async fn working_diff(
            &self,
            _workspace_id: Uuid,
        ) -> anyhow::Result<Vec<crate::application::dto::diff::TextDiffResult>> {
            unimplemented!()
        }

        async fn commit_diff(
            &self,
            _workspace_id: Uuid,
            _from: &str,
            _to: &str,
        ) -> anyhow::Result<Vec<crate::application::dto::diff::TextDiffResult>> {
            unimplemented!()
        }

        async fn history(
            &self,
            _workspace_id: Uuid,
        ) -> anyhow::Result<Vec<crate::application::dto::git::GitCommitInfo>> {
            unimplemented!()
        }

        async fn sync(
            &self,
            _workspace_id: Uuid,
            req: &GitSyncRequestDto,
            _cfg: Option<&crate::application::ports::git_repository::UserGitCfg>,
        ) -> anyhow::Result<crate::application::dto::git::GitSyncOutcome> {
            self.outcomes.lock().unwrap().push(req.clone());
            if let Some(err) = self.failures.lock().unwrap().pop_front() {
                Err(err)
            } else {
                Ok(crate::application::dto::git::GitSyncOutcome {
                    files_changed: 1,
                    commit_hash: Some("abc123".into()),
                    pushed: false,
                    message: "ok".into(),
                })
            }
        }
    }

    struct RecordingJobQueue {
        complete: Mutex<Vec<i64>>,
        failed: Mutex<Vec<i64>>,
    }

    impl RecordingJobQueue {
        fn new() -> Self {
            Self {
                complete: Mutex::new(Vec::new()),
                failed: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl GitRebuildJobQueue for RecordingJobQueue {
        async fn enqueue(
            &self,
            _workspace_id: Uuid,
            _actor_id: Option<Uuid>,
            _permission_snapshot: &[String],
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn fetch_next(
            &self,
            _lock_timeout_secs: i64,
        ) -> anyhow::Result<Option<GitRebuildJob>> {
            Ok(None)
        }

        async fn complete(&self, job_id: i64) -> anyhow::Result<()> {
            self.complete.lock().unwrap().push(job_id);
            Ok(())
        }

        async fn fail(&self, job_id: i64, _error: &str) -> anyhow::Result<()> {
            self.failed.lock().unwrap().push(job_id);
            Ok(())
        }
    }

    struct RecordingGitRepo {
        last_status: Mutex<Option<String>>,
    }

    impl RecordingGitRepo {
        fn new() -> Self {
            Self {
                last_status: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl GitRepository for RecordingGitRepo {
        async fn get_config(
            &self,
            _user_id: Uuid,
        ) -> anyhow::Result<
            Option<(
                Uuid,
                String,
                String,
                String,
                bool,
                chrono::DateTime<chrono::Utc>,
                chrono::DateTime<chrono::Utc>,
            )>,
        > {
            unimplemented!()
        }

        async fn upsert_config(
            &self,
            _user_id: Uuid,
            _repository_url: &str,
            _branch_name: Option<&str>,
            _auth_type: &str,
            _auth_data: &serde_json::Value,
            _auto_sync: Option<bool>,
        ) -> anyhow::Result<(
            Uuid,
            String,
            String,
            String,
            bool,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )> {
            unimplemented!()
        }

        async fn delete_config(&self, _user_id: Uuid) -> anyhow::Result<bool> {
            unimplemented!()
        }

        async fn load_user_git_cfg(
            &self,
            _user_id: Uuid,
        ) -> anyhow::Result<Option<crate::application::ports::git_repository::UserGitCfg>> {
            Ok(None)
        }

        async fn get_last_sync_log(
            &self,
            _user_id: Uuid,
        ) -> anyhow::Result<
            Option<(
                Option<chrono::DateTime<chrono::Utc>>,
                Option<String>,
                Option<String>,
                Option<String>,
            )>,
        > {
            Ok(None)
        }

        async fn log_sync_operation(
            &self,
            _workspace_id: Uuid,
            _operation: &str,
            status: &str,
            _message: Option<&str>,
            _commit_hash: Option<&str>,
        ) -> anyhow::Result<()> {
            *self.last_status.lock().unwrap() = Some(status.to_string());
            Ok(())
        }

        async fn delete_sync_logs(&self, _workspace_id: Uuid) -> anyhow::Result<()> {
            Ok(())
        }

        async fn delete_repository_state(&self, _workspace_id: Uuid) -> anyhow::Result<()> {
            Ok(())
        }

        async fn list_auto_sync_workspaces(&self) -> anyhow::Result<Vec<Uuid>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn successful_job_updates_metrics() {
        let queue = Arc::new(RecordingJobQueue::new());
        let workspace = Arc::new(RecordingWorkspace::new());
        let git_repo = Arc::new(RecordingGitRepo::new());
        let metrics = Arc::new(MetricsRegistry::default());
        let svc = GitRebuildService::new(queue.clone(), workspace, git_repo, metrics.clone());
        let job = GitRebuildJob {
            id: 1,
            workspace_id: Uuid::new_v4(),
            actor_id: None,
            attempts: 1,
            permission_snapshot: vec!["git:sync".into()],
        };
        svc.process_job(&job).await.unwrap();
        assert_eq!(queue.complete.lock().unwrap().as_slice(), &[1]);
        assert_eq!(metrics.snapshot().git_rebuild_success, 1);
    }

    #[tokio::test]
    async fn failing_job_retries_and_counts_metrics() {
        let queue = Arc::new(RecordingJobQueue::new());
        let workspace = Arc::new(RecordingWorkspace::new());
        workspace.fail_with(anyhow::anyhow!("broken"));
        let git_repo = Arc::new(RecordingGitRepo::new());
        let metrics = Arc::new(MetricsRegistry::default());
        let svc = GitRebuildService::new(queue.clone(), workspace, git_repo, metrics.clone());
        let job = GitRebuildJob {
            id: 2,
            workspace_id: Uuid::new_v4(),
            actor_id: None,
            attempts: 0,
            permission_snapshot: vec!["git:sync".into()],
        };
        svc.process_job(&job).await.unwrap();
        assert_eq!(queue.failed.lock().unwrap().as_slice(), &[2]);
        assert_eq!(metrics.snapshot().git_rebuild_retry, 1);
    }

    #[tokio::test]
    async fn forced_retry_failure_routes_through_error_handler() {
        let queue = Arc::new(RecordingJobQueue::new());
        let workspace = Arc::new(RecordingWorkspace::new());
        workspace.fail_with(anyhow::anyhow!("non-fast-forward push rejected"));
        workspace.fail_with(anyhow::anyhow!("still broken"));
        let git_repo = Arc::new(RecordingGitRepo::new());
        let metrics = Arc::new(MetricsRegistry::default());
        let svc =
            GitRebuildService::new(queue.clone(), workspace.clone(), git_repo, metrics.clone());
        let job = GitRebuildJob {
            id: 3,
            workspace_id: Uuid::new_v4(),
            actor_id: None,
            attempts: 0,
            permission_snapshot: vec!["git:sync".into()],
        };
        svc.process_job(&job).await.unwrap();
        assert_eq!(queue.failed.lock().unwrap().as_slice(), &[3]);
        assert_eq!(metrics.snapshot().git_rebuild_retry, 1);
        let requests = workspace.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].force, Some(false));
        assert_eq!(requests[1].force, Some(true));
    }
}
