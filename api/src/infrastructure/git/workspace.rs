use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use git2::{
    CertificateCheckStatus, Commit, Cred, ErrorClass, FetchOptions, FileMode, Indexer, ObjectType,
    PushOptions, RemoteCallbacks, Repository, Signature, Sort, Time, TreeWalkMode, TreeWalkResult,
};
use sqlx::{Row, types::Json};
use tempfile::{Builder as TempDirBuilder, TempDir};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::application::dto::diff::TextDiffResult;
use crate::application::dto::git::{
    GitChangeItem, GitCommitInfo, GitPullConflictItemDto, GitPullRequestDto, GitPullResultDto,
    GitRemoteCheckDto, GitSyncOutcome, GitSyncRequestDto, GitWorkspaceStatus,
};
use crate::application::ports::git_repository::UserGitCfg;
use crate::application::ports::git_storage::{
    BlobKey, CommitMeta, GitStorage, decode_commit_id, encode_commit_id,
};
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::storage_port::StorageResolverPort;
use crate::application::services::diff::text_diff::compute_text_diff;
use crate::application::services::realtime::snapshot::SnapshotService;
use crate::infrastructure::db::PgPool;
use tokio::fs as async_fs;

pub struct GitWorkspaceService {
    pool: PgPool,
    git_storage: Arc<dyn GitStorage>,
    storage: Arc<dyn StorageResolverPort>,
    snapshot: Arc<SnapshotService>,
}

impl GitWorkspaceService {
    pub fn new(
        pool: PgPool,
        git_storage: Arc<dyn GitStorage>,
        storage: Arc<dyn StorageResolverPort>,
        snapshot: Arc<SnapshotService>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            pool,
            git_storage,
            storage,
            snapshot,
        })
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

    async fn latest_commit_meta(&self, workspace_id: Uuid) -> anyhow::Result<Option<CommitMeta>> {
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

        row.map(|r| row_to_commit_meta(r)).transpose()
    }

    async fn load_commit_meta_ref(
        &self,
        workspace_id: Uuid,
        rev: &str,
    ) -> anyhow::Result<Option<CommitMeta>> {
        if let Some(base) = rev.strip_suffix('^') {
            let Some(meta) = self.commit_meta_by_hex(workspace_id, base).await? else {
                return Ok(None);
            };
            if let Some(parent_id) = meta.parent_commit_id.clone() {
                return self
                    .commit_meta_by_id(workspace_id, parent_id.as_slice())
                    .await;
            }
            return Ok(None);
        }
        self.commit_meta_by_hex(workspace_id, rev).await
    }

    async fn commit_meta_by_id(
        &self,
        workspace_id: Uuid,
        commit_id: &[u8],
    ) -> anyhow::Result<Option<CommitMeta>> {
        let row = sqlx::query(
            r#"SELECT commit_id, parent_commit_id, message, author_name, author_email,
                      committed_at, pack_key, file_hash_index
               FROM git_commits
               WHERE workspace_id = $1 AND commit_id = $2
               LIMIT 1"#,
        )
        .bind(workspace_id)
        .bind(commit_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| row_to_commit_meta(row)).transpose()
    }

    async fn commit_meta_by_hex(
        &self,
        workspace_id: Uuid,
        hex: &str,
    ) -> anyhow::Result<Option<CommitMeta>> {
        let bytes = crate::application::ports::git_storage::decode_commit_id(hex)?;
        let row = sqlx::query(
            r#"SELECT commit_id, parent_commit_id, message, author_name, author_email,
                      committed_at, pack_key, file_hash_index
               FROM git_commits
               WHERE workspace_id = $1 AND commit_id = $2
               LIMIT 1"#,
        )
        .bind(workspace_id)
        .bind(bytes)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| row_to_commit_meta(r)).transpose()
    }

    async fn ensure_latest_meta(&self, workspace_id: Uuid) -> anyhow::Result<Option<CommitMeta>> {
        if let Some(meta) = self.latest_commit_meta(workspace_id).await? {
            return Ok(Some(meta));
        }
        let Some(storage_latest) = self.git_storage.latest_commit(workspace_id).await? else {
            return Ok(None);
        };
        info!(workspace_id = %workspace_id, commit = %encode_commit_id(&storage_latest.commit_id), "git_backfill_latest_from_storage");
        self.backfill_commits_from_storage(workspace_id, &storage_latest)
            .await?;
        Ok(Some(storage_latest))
    }

    async fn bootstrap_remote_history(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
        branch: &str,
    ) -> anyhow::Result<Option<CommitMeta>> {
        let temp_dir = TempDirBuilder::new()
            .prefix("git-bootstrap-")
            .tempdir()
            .map_err(|e| anyhow!(e))?;
        let repo = Repository::init_bare(temp_dir.path())?;

        let Some(remote_head) = fetch_remote_head(&repo, cfg, branch)? else {
            return Ok(None);
        };

        let ordered = {
            let mut revwalk = repo.revwalk()?;
            revwalk.push(remote_head)?;
            revwalk.set_sorting(Sort::TOPOLOGICAL | Sort::REVERSE)?;

            let mut collected = Vec::new();
            for oid_result in revwalk {
                collected.push(oid_result?);
            }
            collected
        };

        if ordered.is_empty() {
            return Ok(None);
        }

        let mut latest_meta = self.git_storage.latest_commit(workspace_id).await?;

        for oid in ordered {
            if self
                .commit_meta_by_id(workspace_id, oid.as_bytes())
                .await?
                .is_some()
            {
                continue;
            }

            let (meta, snapshots, pack_bytes) = {
                let commit = repo.find_commit(oid)?;
                let committed_at = git_time_to_datetime(commit.time())?;
                let message = commit
                    .message()
                    .map(|m| m.trim_end_matches('\n').to_string())
                    .filter(|m| !m.trim().is_empty());
                let author = commit.author();
                let author_name = author.name().map(|s| s.to_string());
                let author_email = author.email().map(|s| s.to_string());
                let parent_commit_id = if commit.parent_count() > 0 {
                    let parent = commit.parent_id(0)?;
                    Some(parent.as_bytes().to_vec())
                } else {
                    None
                };

                let files = read_commit_files(&repo, oid.as_bytes())?;
                let mut snapshots: HashMap<String, FileSnapshot> = HashMap::new();
                let mut file_hash_index: HashMap<String, String> = HashMap::new();
                for (path, bytes) in files.into_iter() {
                    let hash = sha256_hex(&bytes);
                    let is_text = std::str::from_utf8(&bytes).is_ok();
                    file_hash_index.insert(path.clone(), hash.clone());
                    snapshots.insert(
                        path,
                        FileSnapshot {
                            hash,
                            data: FileSnapshotData::Inline(bytes),
                            is_text,
                        },
                    );
                }

                let mut pack_builder = repo.packbuilder()?;
                pack_builder.insert_commit(oid)?;
                let mut pack_buf = git2::Buf::new();
                pack_builder.write_buf(&mut pack_buf)?;
                let pack_bytes = pack_buf.to_vec();
                drop(pack_builder);

                let commit_id = oid.as_bytes().to_vec();
                let pack_key = format!(
                    "git/packs/{}/{}.pack",
                    workspace_id,
                    encode_commit_id(&commit_id)
                );

                let meta = CommitMeta {
                    commit_id,
                    parent_commit_id,
                    message,
                    author_name,
                    author_email,
                    committed_at,
                    pack_key,
                    file_hash_index,
                };

                (meta, snapshots, pack_bytes)
            };

            let prev_latest = latest_meta.clone();
            let snapshot_keys = match self
                .store_commit_snapshots(workspace_id, &meta.commit_id, &snapshots)
                .await
            {
                Ok(keys) => keys,
                Err(err) => {
                    return Err(err);
                }
            };

            if let Err(err) = self
                .git_storage
                .store_pack(workspace_id, &pack_bytes, &meta)
                .await
            {
                for key in snapshot_keys.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                return Err(err);
            }

            if let Err(err) = self
                .git_storage
                .set_latest_commit(workspace_id, Some(&meta))
                .await
            {
                let _ = self
                    .git_storage
                    .delete_pack(workspace_id, &meta.commit_id)
                    .await;
                for key in snapshot_keys.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                let _ = self
                    .git_storage
                    .set_latest_commit(workspace_id, prev_latest.as_ref())
                    .await;
                return Err(err);
            }

            let mut tx = self.pool.begin().await?;
            let insert_res = sqlx::query(
                r#"INSERT INTO git_commits (
                        commit_id,
                        parent_commit_id,
                        workspace_id,
                        message,
                        author_name,
                        author_email,
                        committed_at,
                        pack_key,
                        file_hash_index
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                    ON CONFLICT (workspace_id, commit_id) DO NOTHING"#,
            )
            .bind(meta.commit_id.clone())
            .bind(meta.parent_commit_id.clone())
            .bind(workspace_id)
            .bind(meta.message.clone())
            .bind(meta.author_name.clone())
            .bind(meta.author_email.clone())
            .bind(meta.committed_at)
            .bind(meta.pack_key.clone())
            .bind(Json(&meta.file_hash_index))
            .execute(&mut *tx)
            .await;

            if let Err(err) = insert_res {
                tx.rollback().await.ok();
                let _ = self
                    .git_storage
                    .delete_pack(workspace_id, &meta.commit_id)
                    .await;
                for key in snapshot_keys.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                let _ = self
                    .git_storage
                    .set_latest_commit(workspace_id, prev_latest.as_ref())
                    .await;
                return Err(err.into());
            }

            if let Err(err) = sqlx::query(
                "UPDATE git_repository_state SET updated_at = now() WHERE workspace_id = $1",
            )
            .bind(workspace_id)
            .execute(&mut *tx)
            .await
            {
                tx.rollback().await.ok();
                let _ = self
                    .git_storage
                    .delete_pack(workspace_id, &meta.commit_id)
                    .await;
                for key in snapshot_keys.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                let _ = self
                    .git_storage
                    .set_latest_commit(workspace_id, prev_latest.as_ref())
                    .await;
                return Err(err.into());
            }

            if let Err(err) = tx.commit().await {
                let _ = self
                    .git_storage
                    .delete_pack(workspace_id, &meta.commit_id)
                    .await;
                for key in snapshot_keys.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                let _ = self
                    .git_storage
                    .set_latest_commit(workspace_id, prev_latest.as_ref())
                    .await;
                return Err(err.into());
            }

            latest_meta = Some(meta);
        }

        drop(repo);
        let _ = temp_dir.close();
        self.git_storage.latest_commit(workspace_id).await
    }

    async fn backfill_commits_from_storage(
        &self,
        workspace_id: Uuid,
        latest: &CommitMeta,
    ) -> anyhow::Result<()> {
        let mut pending = Vec::new();
        let mut cursor = Some(latest.clone());
        while let Some(meta) = cursor {
            if self
                .commit_meta_by_id(workspace_id, meta.commit_id.as_slice())
                .await?
                .is_some()
            {
                break;
            }
            pending.push(meta.clone());
            cursor = match meta.parent_commit_id.clone() {
                Some(parent) => {
                    self.git_storage
                        .commit_meta(workspace_id, parent.as_slice())
                        .await?
                }
                None => None,
            };
        }
        if pending.is_empty() {
            return Ok(());
        }
        pending.reverse();
        let mut tx = self.pool.begin().await?;
        for meta in pending.into_iter() {
            sqlx::query(
                r#"INSERT INTO git_commits (
                        commit_id,
                        parent_commit_id,
                        workspace_id,
                        message,
                        author_name,
                        author_email,
                        committed_at,
                        pack_key,
                        file_hash_index
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                    ON CONFLICT (workspace_id, commit_id) DO NOTHING"#,
            )
            .bind(meta.commit_id.clone())
            .bind(meta.parent_commit_id.clone())
            .bind(workspace_id)
            .bind(meta.message.clone())
            .bind(meta.author_name.clone())
            .bind(meta.author_email.clone())
            .bind(meta.committed_at)
            .bind(meta.pack_key.clone())
            .bind(Json(&meta.file_hash_index))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn collect_commit_chain(
        &self,
        workspace_id: Uuid,
        start: CommitMeta,
    ) -> anyhow::Result<Vec<CommitMeta>> {
        let mut chain = Vec::new();
        let mut cursor = Some(start);
        while let Some(meta) = cursor {
            chain.push(meta.clone());
            cursor = match meta.parent_commit_id.clone() {
                Some(parent) => {
                    self.commit_meta_by_id(workspace_id, parent.as_slice())
                        .await?
                }
                None => None,
            };
        }
        Ok(chain)
    }

    async fn remove_commits(
        &self,
        workspace_id: Uuid,
        commits: &[CommitMeta],
    ) -> anyhow::Result<()> {
        for meta in commits {
            let commit_hex = encode_commit_id(&meta.commit_id);
            if let Err(error) = self
                .git_storage
                .delete_pack(workspace_id, &meta.commit_id)
                .await
            {
                warn!(
                    workspace_id = %workspace_id,
                    commit = %commit_hex,
                    error = ?error,
                    "git_commit_cleanup_pack_failed"
                );
            }
            for path in meta.file_hash_index.keys() {
                let key = blob_key(workspace_id, &meta.commit_id, path);
                if let Err(error) = self.git_storage.delete_blob(&key).await {
                    warn!(
                        workspace_id = %workspace_id,
                        commit = %commit_hex,
                        path = %path,
                        error = ?error,
                        "git_commit_cleanup_blob_failed"
                    );
                }
            }
            sqlx::query("DELETE FROM git_commits WHERE workspace_id = $1 AND commit_id = $2")
                .bind(workspace_id)
                .bind(meta.commit_id.clone())
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    async fn realign_commit_history(
        &self,
        workspace_id: Uuid,
        storage_latest: Option<CommitMeta>,
        db_latest: Option<CommitMeta>,
    ) -> anyhow::Result<()> {
        match (storage_latest, db_latest) {
            (Some(storage), Some(db)) => {
                if storage.commit_id == db.commit_id {
                    return Ok(());
                }
                let storage_id = storage.commit_id.clone();
                let mut cursor = Some(db.clone());
                let mut reached_storage = false;
                let mut to_prune: Vec<CommitMeta> = Vec::new();
                while let Some(meta) = cursor.clone() {
                    if meta.commit_id == storage_id {
                        reached_storage = true;
                        break;
                    }
                    to_prune.push(meta.clone());
                    cursor = match meta.parent_commit_id.clone() {
                        Some(parent) => {
                            self.commit_meta_by_id(workspace_id, parent.as_slice())
                                .await?
                        }
                        None => None,
                    };
                }
                if !reached_storage {
                    let all = self.collect_commit_chain(workspace_id, db.clone()).await?;
                    if !all.is_empty() {
                        info!(
                            workspace_id = %workspace_id,
                            removed = all.len(),
                            "git_commit_pointer_reset_db_chain"
                        );
                        self.remove_commits(workspace_id, &all).await?;
                    }
                } else if !to_prune.is_empty() {
                    info!(
                        workspace_id = %workspace_id,
                        removed = to_prune.len(),
                        "git_commit_pointer_pruned_db_commits"
                    );
                    self.remove_commits(workspace_id, &to_prune).await?;
                }
                self.backfill_commits_from_storage(workspace_id, &storage)
                    .await?;
            }
            (Some(storage), None) => {
                self.backfill_commits_from_storage(workspace_id, &storage)
                    .await?;
            }
            (None, Some(db)) => {
                let all = self.collect_commit_chain(workspace_id, db).await?;
                if !all.is_empty() {
                    info!(
                        workspace_id = %workspace_id,
                        removed = all.len(),
                        "git_commit_pointer_dropped_db_history"
                    );
                    self.remove_commits(workspace_id, &all).await?;
                }
            }
            (None, None) => {}
        }
        Ok(())
    }

    async fn prune_commits_from_head(
        &self,
        workspace_id: Uuid,
        commits: &[CommitMeta],
    ) -> anyhow::Result<()> {
        if commits.is_empty() {
            return Ok(());
        }
        self.remove_commits(workspace_id, commits).await?;
        let new_latest = self.latest_commit_meta(workspace_id).await?;
        self.git_storage
            .set_latest_commit(workspace_id, new_latest.as_ref())
            .await?;
        Ok(())
    }

    async fn ensure_storage_commit_integrity(&self, workspace_id: Uuid) -> anyhow::Result<()> {
        loop {
            let Some(latest) = self.latest_commit_meta(workspace_id).await? else {
                self.git_storage
                    .set_latest_commit(workspace_id, None)
                    .await?;
                return Ok(());
            };
            let chain = self
                .collect_commit_chain(workspace_id, latest.clone())
                .await?;
            let mut missing_idx: Option<usize> = None;
            for (idx, meta) in chain.iter().enumerate() {
                match self
                    .git_storage
                    .commit_meta(workspace_id, meta.commit_id.as_slice())
                    .await?
                {
                    Some(_) => continue,
                    None => {
                        missing_idx = Some(idx);
                        break;
                    }
                }
            }
            if let Some(idx) = missing_idx {
                let to_remove: Vec<CommitMeta> = chain[..=idx].to_vec();
                info!(
                    workspace_id = %workspace_id,
                    removed = to_remove.len(),
                    missing_commit = %encode_commit_id(&chain[idx].commit_id),
                    "git_commit_pointer_pruned_missing_storage_meta"
                );
                self.prune_commits_from_head(workspace_id, &to_remove)
                    .await?;
                continue;
            }
            break;
        }
        Ok(())
    }

    async fn collect_current_state(
        &self,
        workspace_id: Uuid,
    ) -> anyhow::Result<HashMap<String, FileSnapshot>> {
        let mut state: HashMap<String, FileSnapshot> = HashMap::new();

        let doc_rows = sqlx::query(
            "SELECT id, desired_path FROM documents WHERE owner_id = $1 AND type <> 'folder'",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        for row in doc_rows {
            let doc_id: Uuid = row.get("id");
            let export = match self.snapshot.export_current_markdown(&doc_id).await? {
                Some(export) => export,
                None => continue,
            };
            let repo_path = export
                .repo_path
                .or_else(|| row.try_get::<String, _>("desired_path").ok())
                .map(normalize_repo_path)
                .ok_or_else(|| anyhow!("missing_repo_path_for_doc {}", doc_id))?;
            state.insert(
                repo_path,
                FileSnapshot {
                    hash: export.content_hash,
                    data: FileSnapshotData::Inline(export.bytes),
                    is_text: true,
                },
            );
        }

        let attachment_rows = sqlx::query(
            r#"SELECT f.id AS file_id, f.storage_path, f.content_hash
               FROM files f
               JOIN documents d ON d.id = f.document_id
               WHERE d.owner_id = $1"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        for row in attachment_rows {
            let file_id: Uuid = row.get("file_id");
            let storage_path: String = row.get("storage_path");
            let stored_hash: Option<String> = row
                .try_get("content_hash")
                .ok()
                .and_then(|h: String| if h.is_empty() { None } else { Some(h) });
            let (hash, needs_persist) = match stored_hash {
                Some(existing) => (existing, false),
                None => {
                    let computed = self
                        .compute_attachment_hash(&storage_path)
                        .await
                        .with_context(|| {
                            format!("failed to compute attachment hash for {}", storage_path)
                        })?;
                    match computed {
                        Some(value) => (value, true),
                        None => continue,
                    }
                }
            };
            if needs_persist {
                if let Err(err) = self.persist_attachment_hash(file_id, &hash).await {
                    warn!(
                        file_id = %file_id,
                        path = storage_path.as_str(),
                        error = ?err,
                        "git_workspace_attachment_hash_persist_failed"
                    );
                }
            }
            let repo_path = repo_relative_path(&storage_path)?;
            state.insert(
                repo_path,
                FileSnapshot {
                    hash,
                    data: FileSnapshotData::StoragePath(storage_path),
                    is_text: false,
                },
            );
        }

        Ok(state)
    }

    async fn compute_attachment_hash(&self, storage_path: &str) -> anyhow::Result<Option<String>> {
        let abs = self.storage.absolute_from_relative(storage_path);
        match self.storage.read_bytes(abs.as_path()).await {
            Ok(bytes) => Ok(Some(sha256_hex(&bytes))),
            Err(err) => {
                if let Some(io_err) = err.downcast_ref::<io::Error>() {
                    if io_err.kind() == io::ErrorKind::NotFound {
                        return Ok(None);
                    }
                }
                if err.to_string().to_lowercase().contains("not found") {
                    return Ok(None);
                }
                Err(err)
            }
        }
    }

    async fn persist_attachment_hash(&self, file_id: Uuid, hash: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"UPDATE files SET content_hash = $2, updated_at = now()
               WHERE id = $1"#,
        )
        .bind(file_id)
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(())
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
            let is_text: bool = r.get("is_text");
            let op: String = r.get("op");
            let content_hash: Option<String> = r.try_get("content_hash").ok();
            out.push(DirtyRow {
                path,
                is_text,
                op,
                content_hash,
            });
        }
        Ok(out)
    }

    async fn clear_dirty(&self, workspace_id: Uuid) -> anyhow::Result<u64> {
        let res = sqlx::query("DELETE FROM git_dirty_files WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    async fn export_markdown_for_repo_path(
        &self,
        workspace_id: Uuid,
        repo_path: &str,
    ) -> anyhow::Result<Option<(Vec<u8>, String)>> {
        let trimmed = repo_path.trim_start_matches('/');
        let mut candidates: Vec<(&str, bool)> = vec![(trimmed, false)];
        if let Some(stripped) = trimmed.strip_prefix("Archives/") {
            if !stripped.is_empty() {
                candidates.push((stripped, true));
            }
        }

        for (candidate, archived_only) in candidates {
            let row = if archived_only {
                sqlx::query(
                    "SELECT id FROM documents WHERE owner_id = $1 AND desired_path = $2 AND archived_at IS NOT NULL AND type <> 'folder' LIMIT 1",
                )
                .bind(workspace_id)
                .bind(candidate)
                .fetch_optional(&self.pool)
                .await?
            } else {
                sqlx::query(
                    "SELECT id FROM documents WHERE owner_id = $1 AND desired_path = $2 AND type <> 'folder' LIMIT 1",
                )
                .bind(workspace_id)
                .bind(candidate)
                .fetch_optional(&self.pool)
                .await?
            };

            if let Some(row) = row {
                let doc_id: Uuid = row.get("id");
                if let Some(export) = self.snapshot.export_current_markdown(&doc_id).await? {
                    return Ok(Some((export.bytes, export.content_hash)));
                }
            }
        }

        Ok(None)
    }

    fn compute_deltas(
        &self,
        current: &HashMap<String, FileSnapshot>,
        previous: &HashMap<String, String>,
    ) -> FileDeltaSummary {
        let mut added = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();

        for (path, snapshot) in current.iter() {
            match previous.get(path) {
                None => added.push(path.clone()),
                Some(prev_hash) if prev_hash != &snapshot.hash => modified.push(path.clone()),
                _ => {}
            }
        }

        for path in previous.keys() {
            if !current.contains_key(path) {
                deleted.push(path.clone());
            }
        }

        FileDeltaSummary {
            added,
            modified,
            deleted,
        }
    }

    async fn store_commit_snapshots(
        &self,
        workspace_id: Uuid,
        commit_id: &[u8],
        state: &HashMap<String, FileSnapshot>,
    ) -> anyhow::Result<Vec<BlobKey>> {
        let mut stored = Vec::new();
        for (path, snapshot) in state.iter() {
            let key = blob_key(workspace_id, commit_id, path);
            let bytes = self.snapshot_bytes(snapshot).await?;
            if let Err(err) = self.git_storage.put_blob(&key, &bytes).await {
                for key in stored.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                return Err(err);
            }
            stored.push(key);
        }
        Ok(stored)
    }

    async fn snapshot_bytes(&self, snapshot: &FileSnapshot) -> anyhow::Result<Vec<u8>> {
        match &snapshot.data {
            FileSnapshotData::Inline(bytes) => Ok(bytes.clone()),
            FileSnapshotData::StoragePath(path) => {
                let abs = self.storage.absolute_from_relative(path);
                self.storage.read_bytes(abs.as_path()).await
            }
        }
    }

    async fn load_file_snapshot(
        &self,
        workspace_id: Uuid,
        commit_id: &[u8],
        path: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let key = blob_key(workspace_id, commit_id, path);
        match self.git_storage.fetch_blob(&key).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) => {
                // Treat missing blob as absence (e.g., binary or not stored).
                if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::NotFound {
                        return Ok(None);
                    }
                }
                if err.to_string().contains("not found") {
                    return Ok(None);
                }
                Err(err)
            }
        }
    }

    #[allow(dead_code)]
    async fn state_from_commit_meta(
        &self,
        workspace_id: Uuid,
        meta: &CommitMeta,
    ) -> anyhow::Result<HashMap<String, FileSnapshot>> {
        let mut state: HashMap<String, FileSnapshot> = HashMap::new();
        for path in meta.file_hash_index.keys() {
            let Some(bytes) = self
                .load_file_snapshot(workspace_id, &meta.commit_id, path)
                .await?
            else {
                continue;
            };
            let hash = sha256_hex(&bytes);
            let is_text = std::str::from_utf8(&bytes).is_ok();
            state.insert(
                path.clone(),
                FileSnapshot {
                    hash,
                    data: FileSnapshotData::Inline(bytes),
                    is_text,
                },
            );
        }
        Ok(state)
    }

    async fn apply_state_to_workspace(
        &self,
        workspace_id: Uuid,
        state: &HashMap<String, FileSnapshot>,
        previous_index: &HashMap<String, String>,
    ) -> anyhow::Result<u32> {
        let mut changed: u32 = 0;
        // write/update files
        for (path, snapshot) in state.iter() {
            let rel = format!("{}/{}", workspace_id, path.trim_start_matches('/'));
            let abs = self.storage.absolute_from_relative(&rel);
            if let Some(parent) = abs.parent() {
                async_fs::create_dir_all(parent).await?;
            }
            let bytes = self.snapshot_bytes(snapshot).await?;
            self.storage.write_bytes(abs.as_path(), &bytes).await?;
            changed += 1;
        }
        // remove files missing in next state
        for path in previous_index.keys() {
            if state.contains_key(path) {
                continue;
            }
            let rel = format!("{}/{}", workspace_id, path.trim_start_matches('/'));
            let abs = self.storage.absolute_from_relative(&rel);
            if async_fs::remove_file(&abs).await.is_ok() {
                changed += 1;
            }
        }
        Ok(changed)
    }

    fn build_diff_result(
        &self,
        path: &str,
        old_content: Option<&str>,
        new_content: Option<&str>,
    ) -> TextDiffResult {
        match (old_content, new_content) {
            (Some(old), Some(new)) => compute_text_diff(old, new, path),
            _ => TextDiffResult {
                file_path: path.to_string(),
                diff_lines: Vec::new(),
                old_content: old_content.map(|s| s.to_string()),
                new_content: new_content.map(|s| s.to_string()),
            },
        }
    }

    async fn commit_diff_via_packs(
        &self,
        workspace_id: Uuid,
        from_meta: Option<&CommitMeta>,
        to_meta: &CommitMeta,
    ) -> anyhow::Result<Vec<TextDiffResult>> {
        let (to_pack_dir, to_pack_paths) = self
            .persist_pack_chain(workspace_id, Some(to_meta.commit_id.as_slice()))
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "missing pack data for commit {}",
                    encode_commit_id(&to_meta.commit_id)
                )
            })?;

        let from_pack = if let Some(from_meta) = from_meta {
            if from_meta.commit_id != to_meta.commit_id {
                Some(
                    self.persist_pack_chain(workspace_id, Some(from_meta.commit_id.as_slice()))
                        .await?
                        .ok_or_else(|| {
                            anyhow!(
                                "missing pack data for commit {}",
                                encode_commit_id(&from_meta.commit_id)
                            )
                        })?,
                )
            } else {
                None
            }
        } else {
            None
        };

        let temp_dir = TempDirBuilder::new()
            .prefix("git-diff-")
            .tempdir()
            .map_err(|e| anyhow::anyhow!(e))?;
        let repo = Repository::init_bare(temp_dir.path())?;

        apply_pack_files(&repo, &to_pack_paths)?;
        if let Some((_, ref paths)) = from_pack {
            apply_pack_files(&repo, paths)?;
        }

        let from_files = if let Some(from_meta) = from_meta {
            read_commit_files(&repo, from_meta.commit_id.as_slice())?
        } else {
            HashMap::new()
        };
        let to_files = read_commit_files(&repo, to_meta.commit_id.as_slice())?;

        drop(repo);
        let _ = temp_dir.close();
        drop(to_pack_dir);
        if let Some((dir, _)) = from_pack {
            drop(dir);
        }

        let mut paths: BTreeSet<String> = BTreeSet::new();
        paths.extend(from_files.keys().cloned());
        paths.extend(to_files.keys().cloned());

        let mut results = Vec::new();
        for path in paths {
            let old_bytes = from_files.get(&path);
            let new_bytes = to_files.get(&path);
            let old_content = old_bytes
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(|s| s.to_string());
            let new_content = new_bytes
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(|s| s.to_string());
            if old_content.is_none() && new_content.is_none() {
                if old_bytes.is_some() || new_bytes.is_some() {
                    results.push(self.build_diff_result(&path, None, None));
                }
                continue;
            }
            results.push(self.build_diff_result(
                &path,
                old_content.as_deref(),
                new_content.as_deref(),
            ));
        }
        Ok(results)
    }

    async fn commit_diff_from_storage(
        &self,
        workspace_id: Uuid,
        from_meta: Option<&CommitMeta>,
        to_meta: Option<&CommitMeta>,
    ) -> anyhow::Result<Vec<TextDiffResult>> {
        let Some(to_meta) = to_meta else {
            return Ok(Vec::new());
        };

        let mut paths: BTreeSet<String> = BTreeSet::new();
        if let Some(meta) = from_meta {
            paths.extend(meta.file_hash_index.keys().cloned());
        }
        paths.extend(to_meta.file_hash_index.keys().cloned());

        let mut results = Vec::new();
        for path in paths {
            let old_hash = from_meta.and_then(|meta| meta.file_hash_index.get(&path));
            let new_hash = to_meta.file_hash_index.get(&path);
            if let (Some(old), Some(new)) = (old_hash, new_hash) {
                if old == new {
                    continue;
                }
            }

            let old_bytes = match (from_meta, old_hash) {
                (Some(meta), Some(_)) => {
                    self.load_file_snapshot(workspace_id, meta.commit_id.as_slice(), &path)
                        .await?
                }
                _ => None,
            };
            let new_bytes = match new_hash {
                Some(_) => {
                    self.load_file_snapshot(workspace_id, to_meta.commit_id.as_slice(), &path)
                        .await?
                }
                None => None,
            };

            let old_text = old_bytes
                .as_ref()
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(|s| s.to_string());
            let new_text = new_bytes
                .as_ref()
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(|s| s.to_string());

            if old_text.is_none() && new_text.is_none() {
                if old_bytes.is_some() || new_bytes.is_some() {
                    results.push(self.build_diff_result(&path, None, None));
                }
            } else {
                results.push(self.build_diff_result(
                    &path,
                    old_text.as_deref(),
                    new_text.as_deref(),
                ));
            }
        }

        Ok(results)
    }
}

#[async_trait]
impl GitWorkspacePort for GitWorkspaceService {
    async fn ensure_repository(
        &self,
        workspace_id: Uuid,
        default_branch: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO git_repository_state (workspace_id, initialized, default_branch, initialized_at, updated_at)
               VALUES ($1, true, $2, now(), now())
               ON CONFLICT (workspace_id) DO UPDATE SET
                 initialized = true,
                 default_branch = EXCLUDED.default_branch,
                 initialized_at = COALESCE(git_repository_state.initialized_at, EXCLUDED.initialized_at),
                 updated_at = now()"#,
        )
        .bind(workspace_id)
        .bind(default_branch)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_repository(&self, workspace_id: Uuid) -> anyhow::Result<()> {
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

    async fn status(&self, workspace_id: Uuid) -> anyhow::Result<GitWorkspaceStatus> {
        let state = self.load_repository_state(workspace_id).await?;
        let Some((initialized, branch)) = state else {
            return Ok(GitWorkspaceStatus {
                repository_initialized: false,
                current_branch: None,
                uncommitted_changes: 0,
                untracked_files: 0,
            });
        };
        if !initialized {
            return Ok(GitWorkspaceStatus {
                repository_initialized: false,
                current_branch: Some(branch),
                uncommitted_changes: 0,
                untracked_files: 0,
            });
        }
        // Dirty-driven status: avoid full workspace scan
        let latest = self.latest_commit_meta(workspace_id).await?;
        let previous_index: HashMap<String, String> = latest
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
                        // Existing file: if hash unchanged and hash known, ignore; else modified
                        match d.content_hash.as_ref() {
                            Some(h) if h == prev_hash => {}
                            _ => modified += 1,
                        }
                    } else {
                        // New file
                        added += 1;
                    }
                }
                "delete" => {
                    // Treat as deleted (even if not present in previous index)
                    deleted += 1;
                }
                _ => {}
            }
        }

        Ok(GitWorkspaceStatus {
            repository_initialized: true,
            current_branch: Some(branch),
            uncommitted_changes: modified + deleted,
            untracked_files: added,
        })
    }

    async fn list_changes(&self, workspace_id: Uuid) -> anyhow::Result<Vec<GitChangeItem>> {
        // If repository isn't initialized, nothing to report
        if let Some((initialized, _branch)) = self.load_repository_state(workspace_id).await? {
            if !initialized {
                return Ok(Vec::new());
            }
        } else {
            return Ok(Vec::new());
        }

        // Use dirty set to derive changes without scanning storage
        let latest = self.latest_commit_meta(workspace_id).await?;
        let previous_index: HashMap<String, String> = latest
            .as_ref()
            .map(|c| c.file_hash_index.clone())
            .unwrap_or_default();
        let dirty = self.fetch_dirty(workspace_id).await?;

        let mut change_map: BTreeMap<String, String> = BTreeMap::new();
        for d in dirty.iter() {
            match d.op.as_str() {
                "upsert" => {
                    if let Some(prev_hash) = previous_index.get(&d.path) {
                        // If hash unchanged and we know the new hash, skip reporting
                        match d.content_hash.as_ref() {
                            Some(h) if h == prev_hash => {
                                change_map.remove(&d.path);
                            }
                            _ => {
                                change_map.insert(d.path.clone(), "modified".to_string());
                            }
                        }
                    } else {
                        change_map.insert(d.path.clone(), "untracked".to_string());
                    }
                }
                "delete" => {
                    change_map.insert(d.path.clone(), "deleted".to_string());
                }
                _ => {}
            }
        }

        let changes = change_map
            .into_iter()
            .map(|(path, status)| GitChangeItem { path, status })
            .collect();
        Ok(changes)
    }

    async fn working_diff(&self, workspace_id: Uuid) -> anyhow::Result<Vec<TextDiffResult>> {
        let latest = self.latest_commit_meta(workspace_id).await?;
        let previous_index = latest
            .as_ref()
            .map(|c| c.file_hash_index.clone())
            .unwrap_or_default();
        let current = self.collect_current_state(workspace_id).await?;
        let delta = self.compute_deltas(&current, &previous_index);
        let mut results = Vec::new();

        let latest_commit_id = latest.as_ref().map(|c| c.commit_id.clone());

        for path in delta.added.iter().chain(delta.modified.iter()) {
            if let Some(snapshot) = current.get(path) {
                if snapshot.is_text {
                    let new_bytes = self.snapshot_bytes(snapshot).await?;
                    let new_content = String::from_utf8_lossy(&new_bytes).to_string();
                    let old_bytes = match (&latest_commit_id, previous_index.get(path)) {
                        (Some(commit_id), Some(_)) => {
                            self.load_file_snapshot(workspace_id, commit_id.as_slice(), path)
                                .await?
                        }
                        _ => None,
                    };
                    let old_text = old_bytes.and_then(|b| String::from_utf8(b).ok());
                    results.push(self.build_diff_result(
                        path,
                        old_text.as_deref(),
                        Some(&new_content),
                    ));
                } else {
                    results.push(TextDiffResult {
                        file_path: path.clone(),
                        diff_lines: Vec::new(),
                        old_content: None,
                        new_content: None,
                    });
                }
            }
        }

        for path in delta.deleted {
            let old_bytes = if let (Some(commit_id), Some(_)) =
                (&latest_commit_id, previous_index.get(&path))
            {
                self.load_file_snapshot(workspace_id, commit_id.as_slice(), &path)
                    .await?
            } else {
                None
            };
            let old_text = old_bytes.and_then(|b| String::from_utf8(b).ok());
            results.push(self.build_diff_result(&path, old_text.as_deref(), None));
        }

        Ok(results)
    }

    async fn commit_diff(
        &self,
        workspace_id: Uuid,
        from: &str,
        to: &str,
    ) -> anyhow::Result<Vec<TextDiffResult>> {
        let from_meta = self.load_commit_meta_ref(workspace_id, from).await?;
        let to_meta = self.load_commit_meta_ref(workspace_id, to).await?;

        if let Some(to_meta_ref) = to_meta.as_ref() {
            match self
                .commit_diff_via_packs(workspace_id, from_meta.as_ref(), to_meta_ref)
                .await
            {
                Ok(results) => return Ok(results),
                Err(err) => {
                    warn!(
                        %err,
                        from = from_meta
                            .as_ref()
                            .map(|m| encode_commit_id(&m.commit_id))
                            .unwrap_or_else(|| "(root)".to_string()),
                        to = encode_commit_id(&to_meta_ref.commit_id),
                        "failed to compute commit diff from pack data, using stored snapshots"
                    );
                }
            }
        }

        self.commit_diff_from_storage(workspace_id, from_meta.as_ref(), to_meta.as_ref())
            .await
    }

    async fn history(&self, workspace_id: Uuid) -> anyhow::Result<Vec<GitCommitInfo>> {
        let rows = sqlx::query(
            r#"SELECT commit_id, message, author_name, author_email, committed_at
               FROM git_commits
               WHERE workspace_id = $1
               ORDER BY committed_at DESC
               LIMIT 200"#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        let history = rows
            .into_iter()
            .filter_map(|row| {
                let commit_id: Vec<u8> = row.get("commit_id");
                let message: Option<String> = row.try_get("message").ok();
                let author_name: Option<String> = row.try_get("author_name").ok();
                let author_email: Option<String> = row.try_get("author_email").ok();
                let committed_at: DateTime<Utc> = row.get("committed_at");
                Some(GitCommitInfo {
                    hash: encode_commit_id(&commit_id),
                    message: message.unwrap_or_default(),
                    author_name: author_name.unwrap_or_default(),
                    author_email: author_email.unwrap_or_default(),
                    time: committed_at,
                })
            })
            .collect();
        Ok(history)
    }

    async fn sync(
        &self,
        workspace_id: Uuid,
        req: &GitSyncRequestDto,
        cfg: Option<&UserGitCfg>,
    ) -> anyhow::Result<GitSyncOutcome> {
        let state = self.load_repository_state(workspace_id).await?;
        let Some((state_initialized, state_default_branch)) = state else {
            anyhow::bail!("repository not initialized")
        };
        if !state_initialized {
            anyhow::bail!("repository not initialized")
        }

        let branch_hint = cfg
            .map(|c| c.branch_name.clone())
            .unwrap_or(state_default_branch.clone());

        let mut latest_meta = self.ensure_latest_meta(workspace_id).await?;
        if latest_meta.is_none() {
            if let Some(cfg) = cfg {
                if !cfg.repository_url.is_empty() {
                    // Best-effort attempt to bootstrap remote history; ignore errors (e.g., redirects or auth loops)
                    let _ = self
                        .bootstrap_remote_history(workspace_id, cfg, branch_hint.as_str())
                        .await;
                }
            }
        }

        // Resolve branch without holding a DB lock for long.
        let branch_name = cfg
            .map(|c| c.branch_name.clone())
            .unwrap_or(state_default_branch.clone());
        let force_push = req.force.unwrap_or(false);
        let force_full_scan = req.full_scan.unwrap_or(false);
        let skip_push = req.skip_push.unwrap_or(false);

        latest_meta = self.ensure_latest_meta(workspace_id).await?;

        let mut storage_latest = self.git_storage.latest_commit(workspace_id).await?;
        let mut storage_commit_hex = storage_latest
            .as_ref()
            .map(|m| encode_commit_id(&m.commit_id));
        let mut db_commit_hex = latest_meta.as_ref().map(|m| encode_commit_id(&m.commit_id));
        if storage_commit_hex != db_commit_hex {
            warn!(
                workspace_id = %workspace_id,
                db_commit = ?db_commit_hex,
                storage_commit = ?storage_commit_hex,
                "git_commit_pointer_mismatch_detected"
            );
            if let Some(storage_meta) = storage_latest.as_ref() {
                self.backfill_commits_from_storage(workspace_id, storage_meta)
                    .await?;
                latest_meta = self.latest_commit_meta(workspace_id).await?;
            }
            storage_latest = self.git_storage.latest_commit(workspace_id).await?;
            storage_commit_hex = storage_latest
                .as_ref()
                .map(|m| encode_commit_id(&m.commit_id));
            db_commit_hex = latest_meta.as_ref().map(|m| encode_commit_id(&m.commit_id));
            if storage_commit_hex == db_commit_hex {
                info!(
                    workspace_id = %workspace_id,
                    commit = ?storage_commit_hex,
                    "git_commit_pointer_repaired_from_storage"
                );
            } else {
                warn!(
                    workspace_id = %workspace_id,
                    db_commit = ?db_commit_hex,
                    storage_commit = ?storage_commit_hex,
                    "git_commit_pointer_attempting_realign"
                );
                self.realign_commit_history(
                    workspace_id,
                    storage_latest.clone(),
                    latest_meta.clone(),
                )
                .await?;
                latest_meta = self.ensure_latest_meta(workspace_id).await?;
                storage_latest = self.git_storage.latest_commit(workspace_id).await?;
                storage_commit_hex = storage_latest
                    .as_ref()
                    .map(|m| encode_commit_id(&m.commit_id));
                db_commit_hex = latest_meta.as_ref().map(|m| encode_commit_id(&m.commit_id));
                if storage_commit_hex == db_commit_hex {
                    info!(
                        workspace_id = %workspace_id,
                        commit = ?db_commit_hex,
                        "git_commit_pointer_repaired_by_prune"
                    );
                } else {
                    error!(
                        workspace_id = %workspace_id,
                        db_commit = ?db_commit_hex,
                        storage_commit = ?storage_commit_hex,
                        "git_commit_pointer_irreparable"
                    );
                    anyhow::bail!(
                        "repository latest commit mismatch between database ({db_commit_hex:?}) and storage ({storage_commit_hex:?})"
                    );
                }
            }
        }

        self.ensure_storage_commit_integrity(workspace_id).await?;
        latest_meta = self.latest_commit_meta(workspace_id).await?;

        let previous_index = latest_meta
            .as_ref()
            .map(|c| c.file_hash_index.clone())
            .unwrap_or_default();
        let dirty_rows = self.fetch_dirty(workspace_id).await?;

        // Determine strategy: forced full scan or initial commit uses full state rebuild.
        let use_full_scan = force_full_scan || latest_meta.is_none();

        // Build change sets from dirty rows
        let mut upserts: BTreeMap<String, DirtyUpsert> = BTreeMap::new();
        let mut deletes: BTreeSet<String> = BTreeSet::new();
        if !use_full_scan {
            for row in &dirty_rows {
                match row.op.as_str() {
                    "upsert" => {
                        upserts.insert(
                            row.path.clone(),
                            DirtyUpsert {
                                is_text: row.is_text,
                                content_hash: row.content_hash.clone(),
                            },
                        );
                        // Upsert cancels previous delete on same path if any
                        deletes.remove(&row.path);
                    }
                    "delete" => {
                        upserts.remove(&row.path);
                        deletes.insert(row.path.clone());
                    }
                    _ => {}
                }
            }
        }

        // Filter out no-op upserts by comparing content_hash with previous index if available
        if !use_full_scan {
            upserts.retain(
                |path, u| match (&u.content_hash, previous_index.get(path)) {
                    (Some(hnew), Some(hprev)) if hnew == hprev => false,
                    _ => true,
                },
            );
        }

        // If still nothing to do
        if !use_full_scan && upserts.is_empty() && deletes.is_empty() {
            // Nothing to commit: clear any leftover dirty and exit.
            let _ = self.clear_dirty(workspace_id).await;
            return Ok(GitSyncOutcome {
                files_changed: 0,
                commit_hash: latest_meta.map(|c| encode_commit_id(&c.commit_id)),
                pushed: false,
                message: "nothing to commit".to_string(),
            });
        }

        let committed_at = Utc::now();
        let author_name = "RefMD".to_string();
        let author_email = "refmd@example.com".to_string();
        let message = req
            .message
            .clone()
            .unwrap_or_else(|| "RefMD sync".to_string());

        // Precompute data needed for tree build and meta before creating libgit2 objects
        // This avoids holding non-Send libgit2 types across await points.
        let mut precomputed_full_entries: Option<BTreeMap<String, Vec<u8>>> = None;
        let mut precomputed_upsert_bytes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut changed_text_snapshots: HashMap<String, FileSnapshot> = HashMap::new();
        let mut next_file_hash_index: HashMap<String, String> = previous_index.clone();
        let files_changed_for_response: u32;

        if use_full_scan {
            let current = self.collect_current_state(workspace_id).await?;
            let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            for (path, snapshot) in current.iter() {
                let bytes = self.snapshot_bytes(snapshot).await?;
                entries.insert(path.clone(), bytes);
                next_file_hash_index.insert(path.clone(), snapshot.hash.clone());
            }
            files_changed_for_response = next_file_hash_index.len() as u32;
            precomputed_full_entries = Some(entries);
        } else {
            let mut stale_paths: Vec<String> = Vec::new();
            for (path, up) in upserts.iter() {
                if up.is_text {
                    match self
                        .export_markdown_for_repo_path(workspace_id, path)
                        .await?
                    {
                        Some((bytes, hash)) => {
                            precomputed_upsert_bytes.insert(path.clone(), bytes.clone());
                            next_file_hash_index.insert(path.clone(), hash.clone());
                            changed_text_snapshots.insert(
                                path.clone(),
                                FileSnapshot {
                                    hash,
                                    data: FileSnapshotData::Inline(bytes),
                                    is_text: true,
                                },
                            );
                        }
                        None => {
                            stale_paths.push(path.clone());
                        }
                    }
                    continue;
                }

                let storage_rel = format!("{}/{}", workspace_id, path);
                let abs = self.storage.absolute_from_relative(&storage_rel);
                match self.storage.read_bytes(abs.as_path()).await {
                    Ok(bytes) => {
                        precomputed_upsert_bytes.insert(path.clone(), bytes.clone());
                        let hash = match up.content_hash.as_ref() {
                            Some(h) => h.clone(),
                            None => sha256_hex(&bytes),
                        };
                        next_file_hash_index.insert(path.clone(), hash);
                    }
                    Err(e) => {
                        let skip = e
                            .downcast_ref::<io::Error>()
                            .map(|ioe| ioe.kind() == ErrorKind::NotFound)
                            .unwrap_or_else(|| e.to_string().to_lowercase().contains("not found"));
                        if skip {
                            stale_paths.push(path.clone());
                            continue;
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
            if !stale_paths.is_empty() {
                for p in stale_paths {
                    let _ = sqlx::query(
                        "DELETE FROM git_dirty_files WHERE workspace_id = $1 AND path = $2",
                    )
                    .bind(workspace_id)
                    .bind(&p)
                    .execute(&self.pool)
                    .await;
                }
            }
            for d in deletes.iter() {
                next_file_hash_index.remove(d);
            }
            files_changed_for_response = (upserts.len() + deletes.len()) as u32;
        }

        let previous_pack = if let Some(prev_meta) = latest_meta.as_ref() {
            Some(
                self.persist_pack_chain(workspace_id, Some(prev_meta.commit_id.as_slice()))
                    .await?
                    .ok_or_else(|| {
                        anyhow!(
                            "missing pack data for commit {}",
                            encode_commit_id(&prev_meta.commit_id)
                        )
                    })?,
            )
        } else {
            None
        };

        let (meta, pack_bytes, commit_hex, pushed, files_changed_for_response) = {
            let temp_dir = TempDirBuilder::new()
                .prefix("git-sync-")
                .tempdir()
                .map_err(|e| anyhow::anyhow!(e))?;
            let repo = Repository::init_bare(temp_dir.path())?;

            if let Some((_, ref pack_paths)) = previous_pack {
                // Apply full chain to ensure delta bases are present
                apply_pack_files(&repo, pack_paths)?;
            }

            // Skip pre-fetch/verify to avoid remote redirect/auth loops; rely on push outcome.
            // Build sources from either full scan or dirty set (no awaits here)
            let tree_oid = if use_full_scan {
                let entries = precomputed_full_entries.as_ref().unwrap();
                build_tree_from_entries(&repo, entries)?
            } else {
                // Incremental: reuse previous blobs for unchanged paths
                let mut sources: BTreeMap<String, FileSource> = BTreeMap::new();
                if let Some(prev_meta) = latest_meta.as_ref() {
                    let prev_oids = read_commit_blob_oids(&repo, prev_meta.commit_id.as_slice())?;
                    for (p, oid) in prev_oids {
                        // start from previous
                        sources.insert(p, FileSource::Oid(oid));
                    }
                }
                for d in deletes.iter() {
                    sources.remove(d);
                }
                for (path, bytes) in precomputed_upsert_bytes.iter() {
                    sources.insert(path.clone(), FileSource::Bytes(bytes.clone()));
                }
                build_tree_from_sources(&repo, &sources)?
            };
            let tree = repo.find_tree(tree_oid)?;

            let mut parent_commits = Vec::new();
            if let Some(prev_meta) = latest_meta.as_ref() {
                let parent_oid = git2::Oid::from_bytes(&prev_meta.commit_id)?;
                parent_commits.push(repo.find_commit(parent_oid)?);
            }
            let parent_refs: Vec<&Commit> = parent_commits.iter().collect();

            let branch_ref = format!("refs/heads/{}", branch_name);
            let author_sig = signature_from_parts(&author_name, &author_email, committed_at)?;
            let commit_oid = repo.commit(
                Some(&branch_ref),
                &author_sig,
                &author_sig,
                &message,
                &tree,
                &parent_refs,
            )?;
            let commit_hex = encode_commit_id(commit_oid.as_bytes());

            let mut pack_builder = repo.packbuilder()?;
            pack_builder.insert_commit(commit_oid)?;
            let mut pack_buf = git2::Buf::new();
            pack_builder.write_buf(&mut pack_buf)?;
            let pack_bytes = pack_buf.to_vec();
            drop(pack_builder);
            drop(tree);
            drop(parent_commits);
            drop(author_sig);

            // Use precomputed next_file_hash_index for meta
            let file_hash_index = next_file_hash_index;

            let message_opt = if message.trim().is_empty() {
                None
            } else {
                Some(message.clone())
            };

            let meta = CommitMeta {
                commit_id: commit_oid.as_bytes().to_vec(),
                parent_commit_id: latest_meta.as_ref().map(|c| c.commit_id.clone()),
                message: message_opt,
                author_name: Some(author_name.clone()),
                author_email: Some(author_email.clone()),
                committed_at,
                pack_key: format!("git/packs/{}/{}.pack", workspace_id, commit_hex.clone()),
                file_hash_index,
            };

            let mut pushed = false;
            if let Some(cfg) = cfg {
                if !cfg.repository_url.is_empty() && !skip_push {
                    // Propagate push errors so the caller can retry with force
                    pushed = perform_push(&repo, cfg, &branch_name, commit_oid, force_push)?;
                }
            }

            drop(repo);
            let _ = temp_dir.close();

            // files_changed_for_response computed earlier

            (
                meta,
                pack_bytes,
                commit_hex,
                pushed,
                files_changed_for_response,
            )
        };

        if let Some((dir, _)) = previous_pack {
            drop(dir);
        }

        // Short, focused transaction for DB writes only.
        let mut tx = self.pool.begin().await?;
        // Recheck repository state exists before writing.
        let repo_row2 =
            sqlx::query("SELECT initialized FROM git_repository_state WHERE workspace_id = $1")
                .bind(workspace_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(repo_row2) = repo_row2 else {
            tx.rollback().await.ok();
            anyhow::bail!("repository not initialized")
        };
        let initialized2: bool = repo_row2.get("initialized");
        if !initialized2 {
            tx.rollback().await.ok();
            anyhow::bail!("repository not initialized")
        }

        sqlx::query(
            r#"INSERT INTO git_commits (
                    commit_id,
                    parent_commit_id,
                    workspace_id,
                    message,
                    author_name,
                    author_email,
                    committed_at,
                    pack_key,
                    file_hash_index
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(meta.commit_id.clone())
        .bind(meta.parent_commit_id.clone())
        .bind(workspace_id)
        .bind(meta.message.clone())
        .bind(meta.author_name.clone())
        .bind(meta.author_email.clone())
        .bind(meta.committed_at)
        .bind(meta.pack_key.clone())
        .bind(Json(&meta.file_hash_index))
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE git_repository_state SET updated_at = now() WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&mut *tx)
            .await?;

        // Only store snapshots for changed text files (incremental), or all in initial full scan
        let snapshot_keys = if use_full_scan {
            // full state snapshot
            let current = self.collect_current_state(workspace_id).await?;
            match self
                .store_commit_snapshots(workspace_id, &meta.commit_id, &current)
                .await
            {
                Ok(keys) => keys,
                Err(err) => {
                    tx.rollback().await.ok();
                    return Err(err);
                }
            }
        } else {
            match self
                .store_commit_snapshots(workspace_id, &meta.commit_id, &changed_text_snapshots)
                .await
            {
                Ok(keys) => keys,
                Err(err) => {
                    tx.rollback().await.ok();
                    return Err(err);
                }
            }
        };

        if let Err(err) = self
            .git_storage
            .store_pack(workspace_id, &pack_bytes, &meta)
            .await
        {
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            tx.rollback().await.ok();
            return Err(err);
        }

        if let Err(err) = self
            .git_storage
            .set_latest_commit(workspace_id, Some(&meta))
            .await
        {
            let _ = self
                .git_storage
                .delete_pack(workspace_id, &meta.commit_id)
                .await;
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            tx.rollback().await.ok();
            return Err(err);
        }

        if let Err(err) = tx.commit().await {
            let _ = self
                .git_storage
                .delete_pack(workspace_id, &meta.commit_id)
                .await;
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            let _ = self
                .git_storage
                .set_latest_commit(workspace_id, latest_meta.as_ref())
                .await;
            return Err(err.into());
        }

        // Best-effort clear of processed dirty entries
        let _ = self.clear_dirty(workspace_id).await;
        let outcome_message = if pushed {
            "sync completed".to_string()
        } else if skip_push {
            "sync completed (push skipped)".to_string()
        } else {
            "commit created (push failed)".to_string()
        };

        Ok(GitSyncOutcome {
            files_changed: files_changed_for_response,
            commit_hash: Some(commit_hex),
            pushed,
            message: outcome_message,
        })
    }

    async fn pull(
        &self,
        workspace_id: Uuid,
        req: &GitPullRequestDto,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<GitPullResultDto> {
        let state = self.load_repository_state(workspace_id).await?;
        let Some((initialized, branch_default)) = state else {
            anyhow::bail!("repository not initialized");
        };
        if !initialized {
            anyhow::bail!("repository not initialized");
        }
        if cfg.repository_url.is_empty() {
            anyhow::bail!("remote not configured");
        }

        let branch = if cfg.branch_name.is_empty() {
            branch_default
        } else {
            cfg.branch_name.clone()
        };

        // Ensure remote history exists locally (best effort).
        let _ = self
            .bootstrap_remote_history(workspace_id, cfg, &branch)
            .await;

        let latest_meta = self.latest_commit_meta(workspace_id).await?;
        let base_index: HashMap<String, String> = latest_meta
            .as_ref()
            .map(|m| m.file_hash_index.clone())
            .unwrap_or_default();
        let previous_index = base_index.clone();
        let base_commit = latest_meta.as_ref().map(|m| m.commit_id.clone());

        let temp_dir = TempDirBuilder::new()
            .prefix("git-pull-")
            .tempdir()
            .map_err(|e| anyhow::anyhow!(e))?;
        let repo = Repository::init_bare(temp_dir.path())?;
        if let Some((_, pack_paths)) = self
            .persist_pack_chain(
                workspace_id,
                latest_meta
                    .as_ref()
                    .map(|m| m.commit_id.as_slice()),
            )
            .await?
        {
            apply_pack_files(&repo, &pack_paths)?;
        }

        let remote_oid = {
            let Some(head) = fetch_remote_head(&repo, cfg, &branch)? else {
                return Ok(GitPullResultDto {
                    success: false,
                    message: format!("branch '{branch}' not found on remote"),
                    files_changed: 0,
                    commit_hash: None,
                    conflicts: None,
                    base_commit: base_commit.clone(),
                    remote_commit: None,
                });
            };
            head
        };
        let remote_commit = Some(remote_oid.as_bytes().to_vec());

        let local_oid = latest_meta
            .as_ref()
            .and_then(|m| git2::Oid::from_bytes(&m.commit_id).ok());
        // Detect drift between latest commit and current workspace (dirty rows or actual state diff)
        let dirty_rows = self.fetch_dirty(workspace_id).await?;
        let mut drift_detected = !dirty_rows.is_empty();
        let current_state = self.collect_current_state(workspace_id).await?;
        let mut current_index: HashMap<String, String> = HashMap::new();
        for (path, snapshot) in current_state.iter() {
            current_index.insert(path.clone(), snapshot.hash.clone());
            if base_index.get(path) != Some(&snapshot.hash) {
                drift_detected = true;
            }
        }

        // Do not bail on drift: we preserve workspace edits by synthesizing an "ours" commit below.
        if !drift_detected {
            for path in base_index.keys() {
                if !current_index.contains_key(path) {
                    drift_detected = true;
                    break;
                }
            }
        }

        // Build remote state directly from fetched pack (git2 tree), independent of DB meta.
        fn collect_remote_state(
            repo: &Repository,
            oid: git2::Oid,
        ) -> anyhow::Result<HashMap<String, FileSnapshot>> {
            let commit = repo.find_commit(oid)?;
            let tree = commit.tree()?;
            let mut out: HashMap<String, FileSnapshot> = HashMap::new();

            fn walk(
                repo: &Repository,
                tree: &git2::Tree,
                prefix: &str,
                out: &mut HashMap<String, FileSnapshot>,
            ) -> anyhow::Result<()> {
                for entry in tree.iter() {
                    let name = entry.name().unwrap_or_default();
                    let path = if prefix.is_empty() {
                        name.to_string()
                    } else {
                        format!("{prefix}{name}")
                    };
                    match entry.kind() {
                        Some(git2::ObjectType::Tree) => {
                            if let Some(sub) = entry.to_object(repo)?.as_tree() {
                                walk(repo, sub, &(path.clone() + "/"), out)?;
                            }
                        }
                        Some(git2::ObjectType::Blob) => {
                            let blob = repo.find_blob(entry.id())?;
                            let bytes = blob.content().to_vec();
                            let hash = sha256_hex(&bytes);
                            let is_text = std::str::from_utf8(&bytes).is_ok();
                            out.insert(
                                path,
                                FileSnapshot {
                                    hash,
                                    data: FileSnapshotData::Inline(bytes),
                                    is_text,
                                },
                            );
                        }
                        _ => {}
                    }
                }
                Ok(())
            }

            walk(repo, &tree, "", &mut out)?;
            Ok(out)
        }

        let remote_state = collect_remote_state(&repo, remote_oid)?;
        let mut remote_conflicts: Vec<GitPullConflictItemDto> = Vec::new();
        let mut remote_changed_paths: HashSet<String> = HashSet::new();
        for (path, snap) in remote_state.iter() {
            if base_index.get(path) != Some(&snap.hash) {
                remote_changed_paths.insert(path.clone());
            }
        }
        for path in base_index.keys() {
            if !remote_state.contains_key(path) {
                remote_changed_paths.insert(path.clone());
            }
        }
        for path in remote_changed_paths.into_iter() {
            let ours_bytes = if let Some(snap) = current_state.get(&path) {
                Some(self.snapshot_bytes(snap).await?)
            } else {
                None
            };
            let theirs_bytes = if let Some(snap) = remote_state.get(&path) {
                Some(self.snapshot_bytes(snap).await?)
            } else {
                Some(Vec::new())
            };
            let base_bytes = if let Some(meta) = latest_meta.as_ref() {
                self.load_file_snapshot(workspace_id, meta.commit_id.as_slice(), &path)
                    .await?
            } else {
                None
            };

            let (ours, ours_bin) = as_text_or_binary(path.as_str(), ours_bytes.as_ref());
            let (theirs, theirs_bin) = as_text_or_binary(path.as_str(), theirs_bytes.as_ref());
            let (base, base_bin) = as_text_or_binary(path.as_str(), base_bytes.as_ref());
            let is_binary = ours_bin || theirs_bin || base_bin;

            remote_conflicts.push(GitPullConflictItemDto {
                path: path.clone(),
                is_binary,
                ours,
                theirs,
                base,
                document_id: None,
            });
        }
        // If commit IDs differ but no file-level diff was detected (should be rare),
        // still treat as remote changes to avoid silent application.
        if remote_conflicts.is_empty() {
            if let Some(local_oid_val) = local_oid {
                if remote_oid != local_oid_val {
                    remote_conflicts.push(GitPullConflictItemDto {
                        path: "<remote_changes>".to_string(),
                        is_binary: false,
                        ours: None,
                        theirs: None,
                        base: None,
                        document_id: None,
                    });
                }
            } else {
                // No local commit but remote exists.
                remote_conflicts.push(GitPullConflictItemDto {
                    path: "<remote_changes>".to_string(),
                    is_binary: false,
                    ours: None,
                    theirs: None,
                    base: None,
                    document_id: None,
                });
            }
        }
        let remote_changes = !remote_conflicts.is_empty();
        let requires_resolution = remote_changes && drift_detected;

        // If remote has changes conflicting with local drift and no resolutions are provided, ask client to resolve.
        if requires_resolution && req.resolutions.is_empty() {
            return Ok(GitPullResultDto {
                success: false,
                message: "conflicts detected".to_string(),
                files_changed: 0,
                commit_hash: None,
                conflicts: Some(remote_conflicts),
                base_commit: base_commit.clone(),
                remote_commit: remote_commit.clone(),
            });
        }

        // Allow pull even when dirty changes exist; the current workspace state is treated as "ours".
        // Validation for concurrent edits is handled later by conflict resolution.
        // If remote contains local, treat as fast-forward.
        // If remote contains local and remote has changes, return conflicts (no auto-apply).
        if let Some(local_oid_val) = local_oid {
            if repo.graph_descendant_of(remote_oid, local_oid_val)?
                && requires_resolution
                && req.resolutions.is_empty()
            {
                return Ok(GitPullResultDto {
                    success: false,
                    message: "conflicts detected".to_string(),
                    files_changed: 0,
                    commit_hash: None,
                    conflicts: Some(remote_conflicts),
                    base_commit: base_commit.clone(),
                    remote_commit: remote_commit.clone(),
                });
            }
        }

        // Diverged: merge local into remote (linear, parent = remote)
        let Some(_local_oid_val) = local_oid else {
            anyhow::bail!("no local commit to merge");
        };

        let (meta, pack_bytes, merged_snapshots, commit_hex) = {
            // Build a synthetic "ours" commit from the current workspace state so dirty edits are preserved.
            let synthetic_ours = self.build_synthetic_commit(workspace_id, &repo, remote_oid)?;
            let ours_commit = repo.find_commit(synthetic_ours)?;
            let remote_commit_obj = repo.find_commit(remote_oid)?;
            let index = repo.merge_commits(&ours_commit, &remote_commit_obj, None)?;

            let conflict_items = collect_conflicts(&repo, &index)?;
            if !conflict_items.is_empty() && req.resolutions.is_empty() {
                return Ok(GitPullResultDto {
                    success: false,
                    message: "conflicts detected".to_string(),
                    files_changed: 0,
                    commit_hash: None,
                    conflicts: Some(conflict_items),
                    base_commit: base_commit.clone(),
                    remote_commit: remote_commit.clone(),
                });
            }

            // Collect conflict entries for resolution application
            let mut conflict_entries: Vec<(String, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> =
                Vec::new();
            {
                let mut conflicts_iter = index.conflicts()?;
                while let Some(conflict) = conflicts_iter.next() {
                    let conflict = conflict?;
                    let path = conflict
                        .our
                        .as_ref()
                        .or(conflict.their.as_ref())
                        .or(conflict.ancestor.as_ref())
                        .and_then(|e| std::str::from_utf8(&e.path).ok())
                        .ok_or_else(|| anyhow!("missing conflict path"))?
                        .to_string();

                    let to_bytes =
                        |entry: Option<&git2::IndexEntry>| -> anyhow::Result<Option<Vec<u8>>> {
                            if let Some(e) = entry {
                                let blob = repo.find_blob(e.id)?;
                                Ok(Some(blob.content().to_vec()))
                            } else {
                                Ok(None)
                            }
                        };

                    conflict_entries.push((
                        path,
                        to_bytes(conflict.our.as_ref())?,
                        to_bytes(conflict.their.as_ref())?,
                        to_bytes(conflict.ancestor.as_ref())?,
                    ));
                }
            }

            let resolution_map: std::collections::HashMap<
                String,
                &crate::application::dto::git::GitPullResolutionDto,
            > = req.resolutions.iter().map(|r| (r.path.clone(), r)).collect();

            // Build merged state from resolved index (stage 0) plus user resolutions.
            let mut merged_snapshots: HashMap<String, FileSnapshot> = HashMap::new();
            for entry in index.iter() {
                if index_entry_stage(&entry) != 0 {
                    continue;
                }
                let path = index_entry_path(&entry)?;
                let blob = repo.find_blob(entry.id)?;
                let bytes = blob.content().to_vec();
                let hash = sha256_hex(&bytes);
                let is_text = std::str::from_utf8(&bytes).is_ok();
                merged_snapshots.insert(
                    path,
                    FileSnapshot {
                        hash,
                        data: FileSnapshotData::Inline(bytes),
                        is_text,
                    },
                );
            }

            let mut unresolved: Vec<GitPullConflictItemDto> = Vec::new();

            for (path, ours_bytes, theirs_bytes, base_bytes) in conflict_entries {
                let resolution = resolution_map.get(&path);
                if resolution.is_none() {
                    let (ours_txt, ours_bin) = as_text_or_binary(path.as_str(), ours_bytes.as_ref());
                    let (theirs_txt, theirs_bin) = as_text_or_binary(path.as_str(), theirs_bytes.as_ref());
                    let (base_txt, base_bin) = as_text_or_binary(path.as_str(), base_bytes.as_ref());
                    unresolved.push(GitPullConflictItemDto {
                        path: path.clone(),
                        is_binary: ours_bin || theirs_bin || base_bin,
                        ours: ours_txt,
                        theirs: theirs_txt,
                        base: base_txt,
                        document_id: None,
                    });
                    continue;
                }

                let res = *resolution.unwrap();
                let selected_bytes = match res.choice.as_str() {
                    "ours" => ours_bytes.clone(),
                    "theirs" => theirs_bytes.clone(),
                    "custom_text" => {
                        Some(res.content.clone().unwrap_or_default().into_bytes())
                    }
                    other => anyhow::bail!("unsupported resolution choice {other}"),
                }
                .unwrap_or_default();
                let hash = sha256_hex(&selected_bytes);
                let is_text = std::str::from_utf8(&selected_bytes).is_ok();
                merged_snapshots.insert(
                    path.clone(),
                    FileSnapshot {
                        hash,
                        data: FileSnapshotData::Inline(selected_bytes),
                        is_text,
                    },
                );
            }

            if !unresolved.is_empty() {
                return Ok(GitPullResultDto {
                    success: false,
                    message: "conflicts detected".to_string(),
                    files_changed: 0,
                    commit_hash: None,
                    conflicts: Some(unresolved),
                    base_commit: base_commit.clone(),
                    remote_commit: remote_commit.clone(),
                });
            }

            // Build tree from merged snapshots without async work
            let mut entry_map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            for (path, snap) in merged_snapshots.iter() {
                let bytes = match &snap.data {
                    FileSnapshotData::Inline(b) => b.clone(),
                    FileSnapshotData::StoragePath(_) => {
                        anyhow::bail!("unexpected storage-backed snapshot during pull merge")
                    }
                };
                entry_map.insert(path.clone(), bytes);
            }
            let tree_oid = build_tree_from_entries(&repo, &entry_map)?;
            let tree = repo.find_tree(tree_oid)?;
            let sig = signature_from_parts("RefMD", "refmd@example.com", chrono::Utc::now())?;
            let commit_oid = repo.commit(
                None,
                &sig,
                &sig,
                "Merge remote changes",
                &tree,
                &[&remote_commit_obj],
            )?;

            let mut file_hash_index: HashMap<String, String> = HashMap::new();
            for (path, snap) in merged_snapshots.iter() {
                file_hash_index.insert(path.clone(), snap.hash.clone());
            }

            let mut pack_builder = repo.packbuilder()?;
            pack_builder.insert_commit(commit_oid)?;
            let mut pack_buf = git2::Buf::new();
            pack_builder.write_buf(&mut pack_buf)?;
            let pack_bytes = pack_buf.to_vec();

            let commit_hex = encode_commit_id(commit_oid.as_bytes());
            let meta = CommitMeta {
                commit_id: commit_oid.as_bytes().to_vec(),
                parent_commit_id: Some(remote_oid.as_bytes().to_vec()),
                message: Some("Merge remote changes".to_string()),
                author_name: Some("RefMD".to_string()),
                author_email: Some("refmd@example.com".to_string()),
                committed_at: chrono::Utc::now(),
                pack_key: format!("git/packs/{}/{}.pack", workspace_id, commit_hex),
                file_hash_index,
            };

            (meta, pack_bytes, merged_snapshots, commit_hex)
        };

        let snapshot_keys = self
            .store_commit_snapshots(workspace_id, &meta.commit_id, &merged_snapshots)
            .await?;

        if let Err(err) = self
            .git_storage
            .store_pack(workspace_id, &pack_bytes, &meta)
            .await
        {
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            return Err(err);
        }

        if let Err(err) = self
            .git_storage
            .set_latest_commit(workspace_id, Some(&meta))
            .await
        {
            let _ = self
                .git_storage
                .delete_pack(workspace_id, &meta.commit_id)
                .await;
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            return Err(err);
        }

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"INSERT INTO git_commits (
                    commit_id,
                    parent_commit_id,
                    workspace_id,
                    message,
                    author_name,
                    author_email,
                    committed_at,
                    pack_key,
                    file_hash_index
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"#,
        )
        .bind(meta.commit_id.clone())
        .bind(meta.parent_commit_id.clone())
        .bind(workspace_id)
        .bind(meta.message.clone())
        .bind(meta.author_name.clone())
        .bind(meta.author_email.clone())
        .bind(meta.committed_at)
        .bind(meta.pack_key.clone())
        .bind(Json(&meta.file_hash_index))
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE git_repository_state SET updated_at = now() WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        let files_changed = self
            .apply_state_to_workspace(workspace_id, &merged_snapshots, &previous_index)
            .await?;

        self.clear_dirty(workspace_id).await.ok();

        Ok(GitPullResultDto {
            success: true,
            message: "remote changes merged".to_string(),
            files_changed,
            commit_hash: Some(commit_hex),
            conflicts: None,
            base_commit,
            remote_commit,
        })
    }

    async fn head_commit(&self, workspace_id: Uuid) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .latest_commit_meta(workspace_id)
            .await?
            .map(|m| m.commit_id))
    }

    async fn remote_head(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let state = self.load_repository_state(workspace_id).await?;
        let Some((initialized, branch_default)) = state else {
            anyhow::bail!("repository not initialized");
        };
        if !initialized {
            anyhow::bail!("repository not initialized");
        }
        if cfg.repository_url.is_empty() {
            anyhow::bail!("remote not configured");
        }
        let branch = if cfg.branch_name.is_empty() {
            branch_default
        } else {
            cfg.branch_name.clone()
        };
        let temp_dir = TempDirBuilder::new()
            .prefix("git-remote-head-")
            .tempdir()
            .map_err(|e| anyhow!(e))?;
        let repo = Repository::init_bare(temp_dir.path())?;
        let head = fetch_remote_head(&repo, cfg, &branch)?;
        Ok(head.map(|oid| oid.as_bytes().to_vec()))
    }

    async fn has_pending_changes(&self, workspace_id: Uuid) -> anyhow::Result<bool> {
        let dirty_rows = self.fetch_dirty(workspace_id).await?;
        Ok(!dirty_rows.is_empty())
    }

    // Build a synthetic commit that represents the current workspace state, so dirty edits participate in merge.
    fn build_synthetic_commit(
        &self,
        workspace_id: Uuid,
        repo: &Repository,
        remote_oid: git2::Oid,
    ) -> anyhow::Result<git2::Oid> {
        // Collect current workspace state into blobs and a tree.
        let handle = tokio::runtime::Handle::current();
        let current_state = handle.block_on(self.collect_current_state(workspace_id))?;

        let mut tree_builder = repo.treebuilder(None)?;
        for (path, snapshot) in current_state.iter() {
            let bytes = handle.block_on(self.snapshot_bytes(snapshot))?;
            let blob_oid = repo.blob(&bytes)?;
            let mode = 0o100644;
            tree_builder.insert(Path::new(path), blob_oid, mode)?;
        }
        let tree_oid = tree_builder.write()?;
        let tree = repo.find_tree(tree_oid)?;

        // Create a synthetic commit with remote as parent to anchor the merge base.
        let sig = repo.signature()?;
        let commit_oid = repo.commit(
            Some("refs/heads/synthetic-workspace"),
            &sig,
            &sig,
            "workspace-state",
            &tree,
            &[&repo.find_commit(remote_oid)?],
        )?;
        Ok(commit_oid)
    }

    async fn drift_since_commit(
        &self,
        workspace_id: Uuid,
        base_commit: &[u8],
    ) -> anyhow::Result<bool> {
        let Some(meta) = self.commit_meta_by_id(workspace_id, base_commit).await? else {
            return Ok(true);
        };
        let base_index = meta.file_hash_index;
        let current_state = self.collect_current_state(workspace_id).await?;
        if base_index.len() != current_state.len() {
            return Ok(true);
        }
        for (path, snapshot) in current_state.into_iter() {
            let Some(base_hash) = base_index.get(&path) else {
                return Ok(true);
            };
            if base_hash != &snapshot.hash {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn check_remote(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<GitRemoteCheckDto> {
        if cfg.repository_url.is_empty() {
            return Ok(GitRemoteCheckDto {
                ok: true,
                message: "remote not configured".to_string(),
                reason: Some("no_remote".to_string()),
            });
        }
        let branch = cfg.branch_name.clone();
        let temp_dir = TempDirBuilder::new()
            .prefix("git-check-")
            .tempdir()
            .map_err(|e| anyhow!(e))?;
        let repo = Repository::init_bare(temp_dir.path())?;
        let result = match fetch_remote_head(&repo, cfg, &branch) {
            Ok(Some(_)) => GitRemoteCheckDto {
                ok: true,
                message: "remote reachable".to_string(),
                reason: None,
            },
            Ok(None) => GitRemoteCheckDto {
                ok: false,
                message: format!("branch '{branch}' not found on remote"),
                reason: Some("branch_missing".to_string()),
            },
            Err(err) => {
                let lower = err.to_string().to_lowercase();
                let (reason, msg) = if lower.contains("git_http_auth_redirect") {
                    (
                        Some("auth_required".to_string()),
                        "remote requires authentication or SSO approval".to_string(),
                    )
                } else if lower.contains("git_http_not_found") || lower.contains("status code: 404")
                {
                    (
                        Some("repo_not_found".to_string()),
                        "repository URL or branch not found".to_string(),
                    )
                } else {
                    (None, err.to_string())
                };
                GitRemoteCheckDto {
                    ok: false,
                    message: msg,
                    reason,
                }
            }
        };
        drop(repo);
        let _ = temp_dir.close();
        info!(workspace_id = %workspace_id, ok = %result.ok, reason = ?result.reason, "git_remote_check_completed");
        Ok(result)
    }
}

impl GitWorkspaceService {
    async fn persist_pack_chain(
        &self,
        workspace_id: Uuid,
        until: Option<&[u8]>,
    ) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
        let mut attempts = 0;
        loop {
            match self.git_storage.load_pack_chain(workspace_id, until).await {
                Ok(mut stream) => {
                    let temp_dir = tempfile::tempdir()?;
                    let mut pack_paths = Vec::new();
                    let mut index: usize = 0;
                    while let Some(pack) = stream.next().await {
                        let pack = pack?;
                        let path = temp_dir.path().join(format!("{:08}.pack", index));
                        tokio::fs::write(&path, &pack.bytes).await?;
                        pack_paths.push(path);
                        index += 1;
                    }
                    if pack_paths.is_empty() {
                        return Ok(None);
                    } else {
                        return Ok(Some((temp_dir, pack_paths)));
                    }
                }
                Err(err) => {
                    if attempts == 0 {
                        if let Some(commit_hex) = missing_metadata_commit(&err) {
                            match self
                                .repair_missing_commit_metadata(workspace_id, &commit_hex)
                                .await
                            {
                                Ok(_) => {
                                    attempts += 1;
                                    continue;
                                }
                                Err(repair_err) => {
                                    warn!(
                                        workspace_id = %workspace_id,
                                        commit = %commit_hex,
                                        error = ?repair_err,
                                        "git_commit_metadata_repair_failed"
                                    );
                                }
                            }
                        }
                    }
                    return Err(err);
                }
            }
        }
    }

    async fn repair_missing_commit_metadata(
        &self,
        workspace_id: Uuid,
        start_hex: &str,
    ) -> anyhow::Result<()> {
        let mut current_hex = start_hex.to_string();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current_hex.clone()) {
                break;
            }
            let meta =
                if let Some(meta) = self.commit_meta_by_hex(workspace_id, &current_hex).await? {
                    meta
                } else if let Some(meta) = self
                    .reconstruct_commit_meta_from_pack(workspace_id, &current_hex)
                    .await?
                {
                    meta
                } else {
                    anyhow::bail!(
                        "commit {} not found in database or pack storage",
                        current_hex
                    );
                };
            self.git_storage
                .restore_commit_meta(workspace_id, &meta)
                .await?;
            self.upsert_commit_record(workspace_id, &meta).await?;
            if let Some(parent) = meta.parent_commit_id.as_ref() {
                current_hex = encode_commit_id(parent);
            } else {
                break;
            }
        }
        Ok(())
    }

    async fn upsert_commit_record(
        &self,
        workspace_id: Uuid,
        meta: &CommitMeta,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO git_commits (
                    commit_id,
                    parent_commit_id,
                    workspace_id,
                    message,
                    author_name,
                    author_email,
                    committed_at,
                    pack_key,
                    file_hash_index
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT (workspace_id, commit_id) DO UPDATE SET
                    parent_commit_id = EXCLUDED.parent_commit_id,
                    message = EXCLUDED.message,
                    author_name = EXCLUDED.author_name,
                    author_email = EXCLUDED.author_email,
                    committed_at = EXCLUDED.committed_at,
                    pack_key = EXCLUDED.pack_key,
                    file_hash_index = EXCLUDED.file_hash_index"#,
        )
        .bind(meta.commit_id.clone())
        .bind(meta.parent_commit_id.clone())
        .bind(workspace_id)
        .bind(meta.message.clone())
        .bind(meta.author_name.clone())
        .bind(meta.author_email.clone())
        .bind(meta.committed_at)
        .bind(meta.pack_key.clone())
        .bind(Json(&meta.file_hash_index))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn reconstruct_commit_meta_from_pack(
        &self,
        workspace_id: Uuid,
        commit_hex: &str,
    ) -> anyhow::Result<Option<CommitMeta>> {
        let commit_id = decode_commit_id(commit_hex)?;
        let Some(pack_bytes) = self
            .git_storage
            .fetch_pack_for_commit(workspace_id, &commit_id)
            .await?
        else {
            return Ok(None);
        };
        let temp_dir = tempfile::tempdir()?;
        let repo = Repository::init_bare(temp_dir.path())?;
        apply_pack_to_repo(&repo, &pack_bytes)?;
        let oid = git2::Oid::from_bytes(&commit_id)?;
        let commit = repo.find_commit(oid)?;
        let committed_at = git_time_to_datetime(commit.time())?;
        let message = commit
            .message()
            .map(|m| m.trim_end_matches('\n').to_string())
            .filter(|m| !m.trim().is_empty());
        let author = commit.author();
        let author_name = author.name().map(|s| s.to_string());
        let author_email = author.email().map(|s| s.to_string());
        let parent_commit_id = if commit.parent_count() > 0 {
            let parent = commit.parent_id(0)?;
            Some(parent.as_bytes().to_vec())
        } else {
            None
        };
        let files = read_commit_files(&repo, commit_id.as_slice())?;
        let mut file_hash_index: HashMap<String, String> = HashMap::new();
        for (path, bytes) in files.into_iter() {
            file_hash_index.insert(path, sha256_hex(&bytes));
        }
        let meta = CommitMeta {
            commit_id,
            parent_commit_id,
            message,
            author_name,
            author_email,
            committed_at,
            pack_key: format!("git/packs/{}/{}.pack", workspace_id, commit_hex),
            file_hash_index,
        };
        Ok(Some(meta))
    }
}

fn row_to_commit_meta(row: sqlx::postgres::PgRow) -> anyhow::Result<CommitMeta> {
    let commit_id: Vec<u8> = row.get("commit_id");
    let parent_commit_id: Option<Vec<u8>> = row.try_get("parent_commit_id").ok();
    let message: Option<String> = row.try_get("message").ok();
    let author_name: Option<String> = row.try_get("author_name").ok();
    let author_email: Option<String> = row.try_get("author_email").ok();
    let committed_at: DateTime<Utc> = row.get("committed_at");
    let pack_key: String = row.get("pack_key");
    let file_hash_index: Json<HashMap<String, String>> = row.get("file_hash_index");

    Ok(CommitMeta {
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

fn apply_pack_to_repo(repo: &Repository, pack: &[u8]) -> anyhow::Result<()> {
    let objects_dir = repo.path().join("objects").join("pack");
    fs::create_dir_all(&objects_dir)?;
    let odb = repo.odb()?;
    let mut indexer = Indexer::new(Some(&odb), objects_dir.as_path(), 0o644, true)?;
    indexer.write_all(pack)?;
    indexer.commit()?;
    Ok(())
}

fn missing_metadata_commit(err: &anyhow::Error) -> Option<String> {
    let needle = "metadata not found for commit ";
    for cause in err.chain() {
        let msg = cause.to_string();
        if let Some(idx) = msg.find(needle) {
            let start = idx + needle.len();
            let rest = &msg[start..];
            let commit: String = rest
                .chars()
                .take_while(|ch| ch.is_ascii_hexdigit())
                .collect();
            if !commit.is_empty() {
                return Some(commit);
            }
        }
    }
    None
}

fn apply_pack_files(repo: &Repository, pack_paths: &[PathBuf]) -> anyhow::Result<()> {
    for path in pack_paths {
        let bytes = fs::read(path)?;
        apply_pack_to_repo(repo, &bytes)?;
    }
    Ok(())
}

fn collect_conflicts(
    repo: &Repository,
    index: &git2::Index,
) -> anyhow::Result<Vec<GitPullConflictItemDto>> {
    let mut out = Vec::new();
    let mut conflicts = index.conflicts()?;
    while let Some(conflict) = conflicts.next() {
        let conflict = conflict?;
        let path = conflict
            .our
            .as_ref()
            .or(conflict.their.as_ref())
            .or(conflict.ancestor.as_ref())
            .and_then(|e| std::str::from_utf8(&e.path).ok())
            .unwrap_or("")
            .to_string();

        let to_bytes = |entry: Option<&git2::IndexEntry>| -> anyhow::Result<Option<Vec<u8>>> {
            if let Some(e) = entry {
                let blob = repo.find_blob(e.id)?;
                Ok(Some(blob.content().to_vec()))
            } else {
                Ok(None)
            }
        };

        let ours_bytes = to_bytes(conflict.our.as_ref())?;
        let theirs_bytes = to_bytes(conflict.their.as_ref())?;
        let base_bytes = to_bytes(conflict.ancestor.as_ref())?;

        let (ours, ours_bin) = as_text_or_binary(path.as_str(), ours_bytes.as_ref());
        let (theirs, theirs_bin) = as_text_or_binary(path.as_str(), theirs_bytes.as_ref());
        let (base, base_bin) = as_text_or_binary(path.as_str(), base_bytes.as_ref());
        let is_binary = ours_bin || theirs_bin || base_bin;

        out.push(GitPullConflictItemDto {
            path,
            is_binary,
            ours,
            theirs,
            base,
            document_id: None,
        });
    }
    Ok(out)
}

fn index_entry_path(entry: &git2::IndexEntry) -> anyhow::Result<String> {
    let raw = &entry.path;
    if raw.is_empty() {
        anyhow::bail!("empty index entry path");
    }
    if let Ok(cstr) = std::ffi::CStr::from_bytes_with_nul(raw) {
        Ok(cstr
            .to_str()
            .unwrap_or_default()
            .trim_end_matches('\0')
            .to_string())
    } else {
        Ok(String::from_utf8_lossy(raw).trim_end_matches('\0').to_string())
    }
}

fn index_entry_stage(entry: &git2::IndexEntry) -> i32 {
    ((entry.flags as u32 >> 12) & 0b11) as i32
}

fn as_text_or_binary(path: &str, data: Option<&Vec<u8>>) -> (Option<String>, bool) {
    let Some(bytes) = data else { return (None, false) };
    match std::str::from_utf8(bytes) {
        Ok(s) => (Some(s.to_string()), false),
        Err(_) => {
            let lower = path.to_ascii_lowercase();
            let looks_text = lower.ends_with(".md")
                || lower.ends_with(".markdown")
                || lower.ends_with(".txt")
                || lower.ends_with(".json")
                || lower.ends_with(".yaml")
                || lower.ends_with(".yml")
                || lower.ends_with(".toml")
                || lower.ends_with(".ini");
            if looks_text {
                let lossy = String::from_utf8_lossy(bytes).to_string();
                return (Some(lossy), false);
            }
            (None, true)
        }
    }
}


fn extract_host(url: &str) -> Option<String> {
    let s = url.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let mut parts = s.split('/');
    let host_port = parts.next().unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn default_token_username_for(host: Option<&str>) -> &'static str {
    match host {
        Some(h) if h.contains("github") => "x-access-token",
        Some(h) if h.contains("gitlab") => "oauth2",
        Some(h) if h.contains("dev.azure.com") || h.contains("visualstudio.com") => "pat",
        _ => "git",
    }
}

fn build_remote_callbacks(cfg: &UserGitCfg) -> RemoteCallbacks<'static> {
    let auth_type = cfg.auth_type.clone().unwrap_or_default();
    let auth_data = cfg.auth_data.clone();
    let host_hint = extract_host(&cfg.repository_url);
    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(
        move |_url, username_from_url, _allowed| match auth_type.as_str() {
            "token" => {
                if let Some(token) = auth_data
                    .as_ref()
                    .and_then(|v| v.get("token"))
                    .and_then(|v| v.as_str())
                {
                    let user = username_from_url
                        .unwrap_or(default_token_username_for(host_hint.as_deref()));
                    Cred::userpass_plaintext(user, token)
                } else {
                    Cred::default()
                }
            }
            "ssh" => {
                if let Some(key) = auth_data
                    .as_ref()
                    .and_then(|v| v.get("private_key"))
                    .and_then(|v| v.as_str())
                {
                    let user = username_from_url.unwrap_or("git");
                    Cred::ssh_key_from_memory(user, None, key, None)
                } else {
                    Cred::default()
                }
            }
            _ => Cred::default(),
        },
    );
    callbacks.certificate_check(|_, _| Ok(CertificateCheckStatus::CertificateOk));
    callbacks
}

fn prepare_remote<'repo>(
    repo: &'repo Repository,
    cfg: &UserGitCfg,
) -> anyhow::Result<git2::Remote<'repo>> {
    let mut remote = match repo.find_remote("origin") {
        Ok(remote) => remote,
        Err(_) => repo.remote("origin", &cfg.repository_url)?,
    };
    if remote.url() != Some(cfg.repository_url.as_str()) {
        repo.remote_set_url("origin", &cfg.repository_url)?;
        remote = repo.find_remote("origin")?;
    }
    Ok(remote)
}

fn fetch_remote_head(
    repo: &Repository,
    cfg: &UserGitCfg,
    branch: &str,
) -> anyhow::Result<Option<git2::Oid>> {
    let mut remote = prepare_remote(repo, cfg)?;
    let callbacks = build_remote_callbacks(cfg);
    let mut fetch_options = FetchOptions::new();
    fetch_options.remote_callbacks(callbacks);
    let refspec = format!("refs/heads/{branch}:refs/remotes/origin/{branch}");
    remote
        .fetch(&[&refspec], Some(&mut fetch_options), None)
        .map_err(map_git_http_error)?;
    let reference_name = format!("refs/remotes/origin/{branch}");
    match repo.find_reference(&reference_name) {
        Ok(reference) => Ok(reference.target()),
        Err(err) if err.code() == git2::ErrorCode::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

#[allow(dead_code)]

fn read_commit_files(
    repo: &Repository,
    commit_id: &[u8],
) -> anyhow::Result<HashMap<String, Vec<u8>>> {
    let oid = git2::Oid::from_bytes(commit_id)?;
    let commit = repo.find_commit(oid)?;
    let tree = commit.tree()?;
    let mut files = HashMap::new();
    tree.walk(TreeWalkMode::PreOrder, |root, entry| {
        if entry.kind() == Some(ObjectType::Blob) {
            if let Some(name) = entry.name() {
                if let Ok(blob) = repo.find_blob(entry.id()) {
                    let key = format!("{}{}", root, name);
                    files.insert(key, blob.content().to_vec());
                }
            }
        }
        TreeWalkResult::Ok
    })?;
    Ok(files)
}

fn perform_push(
    repo: &Repository,
    cfg: &UserGitCfg,
    branch: &str,
    commit_oid: git2::Oid,
    force: bool,
) -> anyhow::Result<bool> {
    let ref_name = format!("refs/heads/{}", branch);
    repo.reference(&ref_name, commit_oid, true, "update branch for sync")?;

    let mut remote = prepare_remote(repo, cfg)?;
    let callbacks = build_remote_callbacks(cfg);
    let mut push_options = PushOptions::new();
    push_options.remote_callbacks(callbacks);
    let refspec = if force {
        format!("+refs/heads/{0}:refs/heads/{0}", branch)
    } else {
        format!("refs/heads/{0}:refs/heads/{0}", branch)
    };
    remote
        .push(&[&refspec], Some(&mut push_options))
        .map_err(map_git_http_error)?;
    Ok(true)
}

fn map_git_http_error(err: git2::Error) -> anyhow::Error {
    if err.class() == ErrorClass::Http {
        let msg = err.to_string().to_lowercase();
        if msg.contains("status code: 401")
            || msg.contains("status code: 407")
            || msg.contains("redirect")
        {
            // Avoid leaking raw libgit2 error strings to the user; normalize to a short tag.
            return anyhow!("git_http_auth_redirect");
        }
        if msg.contains("status code: 403") || msg.contains("status code: 404") {
            return anyhow!("git_http_not_found");
        }
    }
    err.into()
}

fn build_tree_from_entries(
    repo: &Repository,
    entries: &BTreeMap<String, Vec<u8>>,
) -> anyhow::Result<git2::Oid> {
    let mut root = DirNode::default();
    for (path, data) in entries.iter() {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            continue;
        }
        insert_into_dir(&mut root, &parts, data.clone());
    }
    write_dir(repo, &root)
}

fn signature_from_parts(
    name: &str,
    email: &str,
    at: DateTime<Utc>,
) -> anyhow::Result<Signature<'static>> {
    let git_time = Time::new(at.timestamp(), 0);
    Signature::new(name, email, &git_time).map_err(anyhow::Error::from)
}

fn git_time_to_datetime(time: Time) -> anyhow::Result<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(time.seconds(), 0)
        .ok_or_else(|| anyhow!("invalid git timestamp"))
}

#[derive(Default)]
struct DirNode {
    entries: BTreeMap<String, DirEntry>,
}

enum DirEntry {
    File(Vec<u8>),
    Oid(git2::Oid),
    Dir(Box<DirNode>),
}

fn insert_into_dir(dir: &mut DirNode, parts: &[&str], data: Vec<u8>) {
    use std::collections::btree_map::Entry;

    if parts.is_empty() {
        return;
    }

    if parts.len() == 1 {
        dir.entries
            .insert(parts[0].to_string(), DirEntry::File(data));
        return;
    }

    match dir.entries.entry(parts[0].to_string()) {
        Entry::Occupied(mut occ) => {
            let next = occ.get_mut();
            match next {
                DirEntry::Dir(child) => insert_into_dir(child, &parts[1..], data),
                DirEntry::File(_) => {
                    let mut new_dir = DirNode::default();
                    insert_into_dir(&mut new_dir, &parts[1..], data);
                    *next = DirEntry::Dir(Box::new(new_dir));
                }
                DirEntry::Oid(_) => {
                    let mut new_dir = DirNode::default();
                    insert_into_dir(&mut new_dir, &parts[1..], data);
                    *next = DirEntry::Dir(Box::new(new_dir));
                }
            }
        }
        Entry::Vacant(vac) => {
            if parts.len() == 1 {
                vac.insert(DirEntry::File(data));
            } else {
                let mut new_dir = DirNode::default();
                insert_into_dir(&mut new_dir, &parts[1..], data);
                vac.insert(DirEntry::Dir(Box::new(new_dir)));
            }
        }
    }
}

fn write_dir(repo: &Repository, dir: &DirNode) -> anyhow::Result<git2::Oid> {
    let mut builder = repo.treebuilder(None)?;
    for (name, entry) in dir.entries.iter() {
        match entry {
            DirEntry::File(content) => {
                let oid = repo.blob(content)?;
                builder.insert(name, oid, FileMode::Blob.into())?;
            }
            DirEntry::Oid(oid) => {
                builder.insert(name, *oid, FileMode::Blob.into())?;
            }
            DirEntry::Dir(child) => {
                let oid = write_dir(repo, child)?;
                builder.insert(name, oid, FileMode::Tree.into())?;
            }
        }
    }
    Ok(builder.write()?)
}

enum FileSnapshotData {
    Inline(Vec<u8>),
    StoragePath(String),
}

struct FileSnapshot {
    hash: String,
    data: FileSnapshotData,
    is_text: bool,
}

struct FileDeltaSummary {
    added: Vec<String>,
    modified: Vec<String>,
    deleted: Vec<String>,
}

struct DirtyRow {
    path: String,
    is_text: bool,
    op: String,
    content_hash: Option<String>,
}

struct DirtyUpsert {
    is_text: bool,
    content_hash: Option<String>,
}

fn repo_relative_path(path: &str) -> anyhow::Result<String> {
    let trimmed = path.trim_start_matches('/');
    let mut parts = trimmed.splitn(2, '/');
    let leading = parts.next().unwrap_or("");
    if let Some(rest) = parts.next() {
        Ok(rest.replace('\\', "/"))
    } else if !leading.is_empty() {
        Ok(leading.replace('\\', "/"))
    } else {
        Err(anyhow!("invalid storage path for repository: {path}"))
    }
}

fn normalize_repo_path(path: String) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        trimmed.replace('\\', "/")
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn blob_key(workspace_id: Uuid, commit_id: &[u8], path: &str) -> BlobKey {
    let encoded_path = urlencoding::encode(path);
    let commit_hex = encode_commit_id(commit_id);
    BlobKey {
        path: format!("{}/{}/{}", workspace_id, commit_hex, encoded_path),
    }
}

enum FileSource {
    Bytes(Vec<u8>),
    Oid(git2::Oid),
}

fn insert_source_into_dir(
    dir: &mut DirNode,
    parts: &[&str],
    source: &FileSource,
) -> anyhow::Result<()> {
    use std::collections::btree_map::Entry;
    if parts.is_empty() {
        return Ok(());
    }
    if parts.len() == 1 {
        match source {
            FileSource::Bytes(data) => {
                dir.entries
                    .insert(parts[0].to_string(), DirEntry::File(data.clone()));
            }
            FileSource::Oid(oid) => {
                dir.entries
                    .insert(parts[0].to_string(), DirEntry::Oid(*oid));
            }
        }
        Ok(())
    } else {
        match dir.entries.entry(parts[0].to_string()) {
            Entry::Occupied(mut occ) => match occ.get_mut() {
                DirEntry::Dir(child) => insert_source_into_dir(child, &parts[1..], source),
                DirEntry::File(_) | DirEntry::Oid(_) => {
                    let mut new_dir = DirNode::default();
                    insert_source_into_dir(&mut new_dir, &parts[1..], source)?;
                    *occ.get_mut() = DirEntry::Dir(Box::new(new_dir));
                    Ok(())
                }
            },
            Entry::Vacant(vac) => {
                let mut new_dir = DirNode::default();
                insert_source_into_dir(&mut new_dir, &parts[1..], source)?;
                vac.insert(DirEntry::Dir(Box::new(new_dir)));
                Ok(())
            }
        }
    }
}

fn read_commit_blob_oids(
    repo: &Repository,
    commit_id: &[u8],
) -> anyhow::Result<HashMap<String, git2::Oid>> {
    let oid = git2::Oid::from_bytes(commit_id)?;
    let commit = repo.find_commit(oid)?;
    let tree = commit.tree()?;
    let mut blobs = HashMap::new();
    tree.walk(TreeWalkMode::PreOrder, |root, entry| {
        if entry.kind() == Some(ObjectType::Blob) {
            if let Some(name) = entry.name() {
                let key = format!("{}{}", root, name);
                blobs.insert(key, entry.id());
            }
        }
        TreeWalkResult::Ok
    })?;
    Ok(blobs)
}

fn build_tree_from_sources(
    repo: &Repository,
    entries: &BTreeMap<String, FileSource>,
) -> anyhow::Result<git2::Oid> {
    // We'll reconstruct a DirNode and then write it, but we need to preserve existing blob OIDs for FileSource::Oid.
    let mut root = DirNode::default();
    for (path, src) in entries.iter() {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            continue;
        }
        insert_source_into_dir(&mut root, &parts, src)?;
    }
    write_dir(repo, &root)
}

// write_dir(repo, &DirNode) now supports DirEntry::Oid, so no extra variant needed
