use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::{Row, types::Json};
use uuid::Uuid;

use application::core::ports::errors::PortResult;
use application::git::ports::git_storage::GitStorage;
use application::git::ports::git_workspace::GitWorkspacePort;
use infrastructure::core::db::PgPool;

pub(crate) struct CliGitWorkspace {
    pool: PgPool,
    git_storage: Arc<dyn GitStorage>,
}

impl CliGitWorkspace {
    pub(crate) fn new(pool: PgPool, git_storage: Arc<dyn GitStorage>) -> Self {
        Self { pool, git_storage }
    }

    async fn load_repository_state(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<(bool, String)>> {
        let row = sqlx::query(
            "SELECT initialized, default_branch FROM git_repository_state WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| (r.get("initialized"), r.get("default_branch"))))
    }

    async fn latest_commit_meta(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<Option<application::git::ports::git_storage::CommitMeta>> {
        let row = sqlx::query(
            r#"SELECT commit_id, parent_commit_id, message, author_name, author_email,
                      committed_at, pack_key, file_hash_index
               FROM git_commits
               WHERE workspace_id = $1
               ORDER BY committed_at DESC
               LIMIT 1"#,
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_commit_meta).transpose()
    }

    async fn fetch_dirty(&self, workspace_id: Uuid) -> anyhow::Result<Vec<DirtyRow>> {
        let rows = sqlx::query(
            r#"SELECT path, is_text, op, content_hash
               FROM git_dirty_files
               WHERE workspace_id = $1
               ORDER BY created_at ASC"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let path: String = r.get("path");
            let op: String = r.get("op");
            let content_hash: Option<String> = r.try_get("content_hash").ok();
            out.push(DirtyRow {
                path,
                op,
                content_hash,
            });
        }
        Ok(out)
    }
}

struct DirtyRow {
    path: String,
    op: String,
    content_hash: Option<String>,
}

#[async_trait::async_trait]
impl GitWorkspacePort for CliGitWorkspace {
    async fn ensure_repository(
        &self,
        _workspace_id: Uuid,
        _default_branch: &str,
    ) -> PortResult<()> {
        Err(anyhow::anyhow!("ensure_repository not supported in refmd CLI").into())
    }

    async fn remove_repository(&self, workspace_id: Uuid) -> PortResult<()> {
        let out: anyhow::Result<()> = async {
            let mut tx = self.pool.begin().await?;
            sqlx::query("DELETE FROM git_dirty_files WHERE workspace_id = $1")
                .bind(workspace_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM git_commits WHERE workspace_id = $1")
                .bind(workspace_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE git_repository_state SET initialized = false, updated_at = now() WHERE workspace_id = $1",
            )
            .bind(workspace_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            self.git_storage.delete_all(workspace_id).await?;
            Ok(())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn status(
        &self,
        workspace_id: Uuid,
    ) -> PortResult<application::git::dtos::GitWorkspaceStatus> {
        let out: anyhow::Result<application::git::dtos::GitWorkspaceStatus> = async {
            let state = self.load_repository_state(workspace_id).await?;
            let Some((initialized, branch)) = state else {
                return Ok(application::git::dtos::GitWorkspaceStatus {
                    repository_initialized: false,
                    current_branch: None,
                    uncommitted_changes: 0,
                    untracked_files: 0,
                });
            };
            if !initialized {
                return Ok(application::git::dtos::GitWorkspaceStatus {
                    repository_initialized: false,
                    current_branch: Some(branch),
                    uncommitted_changes: 0,
                    untracked_files: 0,
                });
            }

            let latest = self.latest_commit_meta(workspace_id).await?;
            let previous_index: std::collections::HashMap<String, String> = latest
                .as_ref()
                .map(|c| c.file_hash_index.clone())
                .unwrap_or_default();

            let dirty = self.fetch_dirty(workspace_id).await?;
            let mut added: u32 = 0;
            let mut modified: u32 = 0;
            let mut deleted: u32 = 0;

            for d in dirty.iter() {
                match d.op.as_str() {
                    "upsert" => {
                        if let Some(prev_hash) = previous_index.get(&d.path) {
                            match d.content_hash.as_ref() {
                                Some(h) if h == prev_hash => {}
                                _ => modified += 1,
                            }
                        } else {
                            added += 1;
                        }
                    }
                    "delete" => {
                        deleted += 1;
                    }
                    _ => {}
                }
            }

            Ok(application::git::dtos::GitWorkspaceStatus {
                repository_initialized: true,
                current_branch: Some(branch),
                uncommitted_changes: modified + deleted,
                untracked_files: added,
            })
        }
        .await;
        out.map_err(Into::into)
    }

    async fn list_changes(
        &self,
        workspace_id: Uuid,
    ) -> PortResult<Vec<application::git::dtos::GitChangeItem>> {
        let out: anyhow::Result<Vec<application::git::dtos::GitChangeItem>> = async {
            if let Some((initialized, _)) = self.load_repository_state(workspace_id).await? {
                if !initialized {
                    return Ok(Vec::new());
                }
            } else {
                return Ok(Vec::new());
            }

            let latest = self.latest_commit_meta(workspace_id).await?;
            let previous_index: std::collections::HashMap<String, String> = latest
                .as_ref()
                .map(|c| c.file_hash_index.clone())
                .unwrap_or_default();
            let dirty = self.fetch_dirty(workspace_id).await?;

            let mut out = Vec::new();
            for d in dirty {
                let status = match d.op.as_str() {
                    "delete" => "deleted",
                    "upsert" => {
                        if previous_index.contains_key(&d.path) {
                            "modified"
                        } else {
                            "added"
                        }
                    }
                    _ => "unknown",
                };
                out.push(application::git::dtos::GitChangeItem {
                    path: d.path,
                    status: status.to_string(),
                });
            }
            Ok(out)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn working_diff(
        &self,
        _workspace_id: Uuid,
    ) -> PortResult<Vec<application::core::dtos::TextDiffResult>> {
        Err(anyhow::anyhow!("working_diff not supported in refmd CLI").into())
    }

    async fn commit_diff(
        &self,
        _workspace_id: Uuid,
        _from: &str,
        _to: &str,
    ) -> PortResult<Vec<application::core::dtos::TextDiffResult>> {
        Err(anyhow::anyhow!("commit_diff not supported in refmd CLI").into())
    }

    async fn history(
        &self,
        _workspace_id: Uuid,
    ) -> PortResult<Vec<application::git::dtos::GitCommitInfo>> {
        Err(anyhow::anyhow!("history not supported in refmd CLI").into())
    }

    async fn sync(
        &self,
        _workspace_id: Uuid,
        _req: &application::git::dtos::GitSyncRequestDto,
        _cfg: Option<&application::git::ports::git_repository::UserGitCfg>,
    ) -> PortResult<application::git::dtos::GitSyncOutcome> {
        Err(anyhow::anyhow!("sync not supported in refmd CLI").into())
    }

    async fn pull(
        &self,
        _workspace_id: Uuid,
        _actor_id: Uuid,
        _req: &application::git::dtos::GitPullRequestDto,
        _cfg: &application::git::ports::git_repository::UserGitCfg,
    ) -> PortResult<application::git::dtos::GitPullResultDto> {
        Err(anyhow::anyhow!("pull not supported in refmd CLI").into())
    }

    async fn import_repository(
        &self,
        _workspace_id: Uuid,
        _actor_id: Uuid,
        _cfg: &application::git::ports::git_repository::UserGitCfg,
    ) -> PortResult<application::git::dtos::GitImportOutcome> {
        Err(anyhow::anyhow!("import not supported in refmd CLI").into())
    }

    async fn head_commit(&self, workspace_id: Uuid) -> PortResult<Option<Vec<u8>>> {
        let out: anyhow::Result<Option<Vec<u8>>> = async {
            Ok(self
                .latest_commit_meta(workspace_id)
                .await?
                .map(|m| m.commit_id))
        }
        .await;
        out.map_err(Into::into)
    }

    async fn remote_head(
        &self,
        _workspace_id: Uuid,
        _cfg: &application::git::ports::git_repository::UserGitCfg,
    ) -> PortResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn has_pending_changes(&self, workspace_id: Uuid) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            let dirty_rows = self.fetch_dirty(workspace_id).await?;
            Ok(!dirty_rows.is_empty())
        }
        .await;
        out.map_err(Into::into)
    }

    async fn drift_since_commit(
        &self,
        workspace_id: Uuid,
        base_commit: &[u8],
    ) -> PortResult<bool> {
        let out: anyhow::Result<bool> = async {
            // CLI helper: fallback to dirty check when full state comparison is not available.
            if self.has_pending_changes(workspace_id).await? {
                return Ok(true);
            }
            // If the base commit is not the latest, consider it stale.
            let latest = self.latest_commit_meta(workspace_id).await?;
            if let Some(meta) = latest
                && meta.commit_id.as_slice() != base_commit
            {
                return Ok(true);
            }
            Ok(false)
        }
        .await;
        out.map_err(Into::into)
    }

    async fn check_remote(
        &self,
        _workspace_id: Uuid,
        _cfg: &application::git::ports::git_repository::UserGitCfg,
    ) -> PortResult<application::git::dtos::GitRemoteCheckDto> {
        Ok(application::git::dtos::GitRemoteCheckDto {
            ok: false,
            message: "remote check not supported in CLI".to_string(),
            reason: Some("unsupported".to_string()),
        })
    }
}

fn row_to_commit_meta(
    row: sqlx::postgres::PgRow,
) -> anyhow::Result<application::git::ports::git_storage::CommitMeta> {
    let commit_id: Vec<u8> = row.get("commit_id");
    let parent_commit_id: Option<Vec<u8>> = row.try_get("parent_commit_id").ok();
    let message: Option<String> = row.try_get("message").ok();
    let author_name: Option<String> = row.try_get("author_name").ok();
    let author_email: Option<String> = row.try_get("author_email").ok();
    let committed_at: DateTime<Utc> = row.get("committed_at");
    let pack_key: String = row.get("pack_key");
    let file_hash_index: Json<std::collections::HashMap<String, String>> =
        row.get("file_hash_index");

    Ok(application::git::ports::git_storage::CommitMeta {
        commit_id,
        parent_commit_id,
        message,
        author_name,
        author_email,
        committed_at,
        pack_key,
        file_hash_index: file_hash_index.0,
    })
}
