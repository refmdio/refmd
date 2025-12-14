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
    GitChangeItem, GitCommitInfo, GitImportOutcome, GitPullConflictItemDto, GitPullRequestDto,
    GitPullResultDto, GitRemoteCheckDto, GitSyncOutcome, GitSyncRequestDto, GitWorkspaceStatus,
};
use crate::application::ports::document_repository::DocumentRepository;
use crate::application::ports::git_repository::UserGitCfg;
use crate::application::ports::git_storage::{
    BlobKey, CommitMeta, GitStorage, decode_commit_id, encode_commit_id,
};
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::realtime_port::RealtimeEngine;
use crate::application::ports::storage_port::StorageResolverPort;
use crate::application::services::diff::text_diff::compute_text_diff;
use crate::application::services::realtime::snapshot::{SnapshotService, snapshot_from_markdown};
use crate::application::utils::hash::sha256_hex;
use crate::infrastructure::db::PgPool;
use tokio::fs as async_fs;

pub struct GitWorkspaceService {
    pool: PgPool,
    git_storage: Arc<dyn GitStorage>,
    storage: Arc<dyn StorageResolverPort>,
    snapshot: Arc<SnapshotService>,
    realtime: Arc<dyn RealtimeEngine>,
    docs: Arc<dyn DocumentRepository>,
}

impl GitWorkspaceService {
    pub fn new(
        pool: PgPool,
        git_storage: Arc<dyn GitStorage>,
        storage: Arc<dyn StorageResolverPort>,
        snapshot: Arc<SnapshotService>,
        realtime: Arc<dyn RealtimeEngine>,
        docs: Arc<dyn DocumentRepository>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            pool,
            git_storage,
            storage,
            snapshot,
            realtime,
            docs,
        })
    }

    fn is_missing_objects(err: &anyhow::Error) -> bool {
        let msg = err.to_string().to_lowercase();
        msg.contains("missing objects") || msg.contains("packfile is missing")
    }

    async fn recover_missing_objects(
        &self,
        workspace_id: Uuid,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<()> {
        // Pick branch from cfg or fallback to repository state default.
        let branch = if cfg.branch_name.is_empty() {
            self.load_repository_state(workspace_id)
                .await?
                .map(|(_, default_branch)| default_branch)
                .unwrap_or_else(|| "main".to_string())
        } else {
            cfg.branch_name.clone()
        };

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
            "UPDATE git_repository_state SET initialized = true, default_branch = $2, updated_at = now() WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .bind(&branch)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let _ = self.git_storage.delete_all(workspace_id).await;
        let _ = self.git_storage.set_latest_commit(workspace_id, None).await;

        // Re-bootstrap remote history (best effort).
        let _ = self
            .bootstrap_remote_history(workspace_id, cfg, branch.as_str())
            .await;
        Ok(())
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

        let pack_bytes_master = read_first_pack(repo.path())?.ok_or_else(|| {
            anyhow!(
                "remote fetch produced no pack files for workspace {}",
                workspace_id
            )
        })?;

        let mut latest_meta = self.git_storage.latest_commit(workspace_id).await?;

        for oid in ordered {
            let existing_meta = self.commit_meta_by_id(workspace_id, oid.as_bytes()).await?;
            let existing_pack = self
                .git_storage
                .fetch_pack_for_commit(workspace_id, oid.as_bytes())
                .await?;
            // Skip only when both DB row and pack already exist.
            if existing_meta.is_some() && existing_pack.is_some() {
                latest_meta = existing_meta;
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

                let pack_builder = repo.packbuilder()?;
                // Use the full remote pack for every commit to avoid thin-pack corruption.
                let pack_bytes = pack_bytes_master.clone();
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
            let upsert_res = sqlx::query(
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
            .execute(&mut *tx)
            .await;

            if let Err(err) = upsert_res {
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

        let doc_rows = self
            .docs
            .list_workspace_documents(workspace_id)
            .await?
            .into_iter()
            .filter(|d| d.doc_type != "folder");

        for doc in doc_rows {
            let export = match self.snapshot.export_current_markdown(&doc.id).await? {
                Some(export) => export,
                None => continue,
            };
            let repo_path = export
                .repo_path
                .or_else(|| Some(doc.desired_path.clone()))
                .map(normalize_repo_path)
                .ok_or_else(|| anyhow!("missing_repo_path_for_doc {}", doc.id))?;
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

        // First try by normalized repo path (documents.path). Fall back to desired_path for older records.
        let all_docs = self.docs.list_workspace_documents(workspace_id).await?;

        for (candidate, archived_only) in candidates {
            let lookup_path = format!("{}/{}", workspace_id, candidate);
            let from_path = self
                .docs
                .get_by_owner_and_path(workspace_id, &lookup_path)
                .await?;

            let doc = if let Some(doc) = from_path {
                Some(doc)
            } else {
                all_docs
                    .iter()
                    .find(|d| normalize_repo_path(d.desired_path.clone()) == candidate)
                    .cloned()
            };

            if let Some(doc) = doc {
                if doc.doc_type == "folder" {
                    continue;
                }
                if archived_only && doc.archived_at.is_none() {
                    continue;
                }
                if let Some(export) = self.snapshot.export_current_markdown(&doc.id).await? {
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

    async fn ensure_folder(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        folder_path: &str,
        cache: &mut HashMap<String, Uuid>,
    ) -> anyhow::Result<Option<Uuid>> {
        let trimmed = folder_path.trim_matches('/');
        if trimmed.is_empty() {
            return Ok(None);
        }

        let mut current_parent: Option<Uuid> = None;
        let mut accumulated = String::new();
        for segment in trimmed.split('/') {
            if !accumulated.is_empty() {
                accumulated.push('/');
            }
            accumulated.push_str(segment);

            if let Some(id) = cache.get(&accumulated) {
                current_parent = Some(*id);
                continue;
            }

            let lookup_path = format!("{}/{}", workspace_id, accumulated);
            if let Some(existing) = self
                .docs
                .get_by_owner_and_path(workspace_id, &lookup_path)
                .await?
            {
                if existing.doc_type != "folder" {
                    anyhow::bail!("path_conflict_not_folder");
                }
                cache.insert(accumulated.clone(), existing.id);
                current_parent = Some(existing.id);
                continue;
            }

            let title = if segment.trim().is_empty() {
                "folder"
            } else {
                segment
            };
            let folder = self
                .docs
                .create_for_user(
                    workspace_id,
                    actor_id,
                    title,
                    current_parent,
                    "folder",
                    None,
                )
                .await?;
            self.docs
                .update_repo_path(folder.id, workspace_id, &accumulated)
                .await?;

            cache.insert(accumulated.clone(), folder.id);
            current_parent = Some(folder.id);
        }

        Ok(current_parent)
    }

    async fn materialize_documents_from_state(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        state: &HashMap<String, FileSnapshot>,
    ) -> anyhow::Result<(u32, u32)> {
        let mut folder_cache: HashMap<String, Uuid> = HashMap::new();
        let mut docs_created: u32 = 0;
        let mut attachments_created: u32 = 0;

        let mut existing_by_desired: HashMap<String, Uuid> = self
            .docs
            .list_workspace_documents(workspace_id)
            .await?
            .into_iter()
            .map(|d| (normalize_repo_path(d.desired_path.clone()), d.id))
            .collect();

        let mut paths: Vec<String> = state.keys().cloned().collect();
        paths.sort();

        for path in paths {
            let snapshot = match state.get(&path) {
                Some(s) => s,
                None => continue,
            };
            let normalized = normalize_repo_path(path.clone());
            let parent_path = normalized
                .rsplitn(2, '/')
                .nth(1)
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty());
            let parent_id = if let Some(ppath) = parent_path.as_ref() {
                self.ensure_folder(workspace_id, actor_id, ppath, &mut folder_cache)
                    .await?
            } else {
                None
            };

            // Skip if document already exists at desired_path
            if existing_by_desired.contains_key(&normalized) {
                continue;
            }

            let filename = normalized
                .rsplit('/')
                .next()
                .unwrap_or(&normalized)
                .to_string();
            let title = filename
                .trim_end_matches(".md")
                .trim_end_matches(".markdown")
                .trim_end_matches(".txt");

            let doc = self
                .docs
                .create_for_user(
                    workspace_id,
                    actor_id,
                    if title.is_empty() { "Document" } else { title },
                    parent_id,
                    "document",
                    None,
                )
                .await?;
            self.docs
                .update_repo_path(doc.id, workspace_id, &normalized)
                .await?;
            docs_created += 1;
            existing_by_desired.insert(normalized.clone(), doc.id);

            let bytes = self.snapshot_bytes(snapshot).await.unwrap_or_default();
            if snapshot.is_text {
                let body = extract_markdown_body(&bytes)
                    .unwrap_or_else(|| std::str::from_utf8(&bytes).unwrap_or_default().to_string());
                let snap_bytes = snapshot_from_markdown(&body);
                let _ = self
                    .realtime
                    .apply_snapshot(&doc.id.to_string(), snap_bytes.as_slice())
                    .await;
                let _ = self.realtime.force_persist(&doc.id.to_string()).await;
            } else {
                // Treat as attachment on the created document
                let storage_path = format!("{}/{}", workspace_id, normalized);
                let hash = snapshot.hash.clone();
                let size = bytes.len() as i64;
                let _ = sqlx::query(
                    r#"INSERT INTO files (document_id, filename, content_type, size, storage_path, content_hash)
                       VALUES ($1,$2,$3,$4,$5,$6)"#,
                )
                .bind(doc.id)
                .bind(&filename)
                .bind::<Option<&str>>(None)
                .bind(size)
                .bind(&storage_path)
                .bind(&hash)
                .execute(&self.pool)
                .await;
                attachments_created += 1;
            }
        }
        Ok((docs_created, attachments_created))
    }

    /// Apply merged markdown files directly to realtime/persistence so documents reflect Pull results.
    async fn apply_merged_to_documents(
        &self,
        workspace_id: Uuid,
        next_state: &HashMap<String, FileSnapshot>,
    ) -> anyhow::Result<()> {
        let doc_rows = self
            .docs
            .list_workspace_documents(workspace_id)
            .await?
            .into_iter()
            .filter(|d| d.doc_type != "folder");

        for doc in doc_rows {
            let doc_id = doc.id;
            let normalized = normalize_repo_path(doc.desired_path.clone());
            let Some(snapshot) = next_state.get(&normalized) else {
                continue;
            };

            if !snapshot.is_text {
                continue;
            }
            let bytes = match self.snapshot_bytes(snapshot).await {
                Ok(b) => b,
                Err(err) => {
                    warn!(document_id = %doc_id, error = ?err, "git_pull_snapshot_bytes_failed");
                    continue;
                }
            };
            let body = match extract_markdown_body(&bytes) {
                Some(b) => b,
                None => continue,
            };
            let snap_bytes =
                crate::application::services::realtime::snapshot::snapshot_from_markdown(&body);
            if let Err(err) = crate::infrastructure::storage::suppress_git_dirty(async {
                self.realtime
                    .apply_snapshot(&doc_id.to_string(), snap_bytes.as_slice())
                    .await?;
                self.realtime.force_persist(&doc_id.to_string()).await
            })
            .await
            {
                warn!(document_id = %doc_id, error = ?err, "git_pull_apply_snapshot_failed");
                continue;
            }
        }
        Ok(())
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

    // Build a synthetic commit from the current workspace state so dirty edits participate in merges.
    fn build_synthetic_commit(
        &self,
        workspace_id: Uuid,
        repo: &Repository,
        base_oid: git2::Oid,
    ) -> anyhow::Result<git2::Oid> {
        // Collect current workspace state into blobs and index entries (supports nested paths).
        let current_state = tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(self.collect_current_state(workspace_id))
        })?;

        let mut index = repo.index()?;
        index.clear()?;

        for (path, snapshot) in current_state.iter() {
            let bytes = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(self.snapshot_bytes(snapshot))
            })?;
            let blob_oid = repo.blob(&bytes)?;

            let entry = git2::IndexEntry {
                ctime: git2::IndexTime::new(0, 0),
                mtime: git2::IndexTime::new(0, 0),
                dev: 0,
                ino: 0,
                mode: 0o100644,
                uid: 0,
                gid: 0,
                file_size: bytes.len() as u32,
                id: blob_oid,
                flags: std::cmp::min(path.as_bytes().len(), 0x0fff) as u16,
                flags_extended: 0,
                path: path.as_bytes().to_vec(),
            };
            index.add(&entry)?;
        }

        let tree_oid = index.write_tree_to(repo)?;
        let tree = repo.find_tree(tree_oid)?;

        // Create a synthetic commit with remote as parent to anchor the merge base.
        // Use an explicit signature so we don't rely on local git config being present.
        let sig = signature_from_parts("RefMD", "refmd@example.com", Utc::now())?;
        let commit_oid = repo.commit(
            Some("refs/heads/synthetic-workspace"),
            &sig,
            &sig,
            "workspace-state",
            &tree,
            &[&repo.find_commit(base_oid)?],
        )?;
        Ok(commit_oid)
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
                    // Bootstrap remote history; propagate errors to avoid proceeding without packs.
                    self.bootstrap_remote_history(workspace_id, cfg, branch_hint.as_str())
                        .await?;
                    latest_meta = self.ensure_latest_meta(workspace_id).await?;
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
        let push_required = cfg
            .as_ref()
            .map(|c| !c.repository_url.is_empty())
            .unwrap_or(false)
            && !skip_push;

        // Ensure latest commit pack exists; if missing, attempt to rebuild from storage/remote or fail early.
        if let Some(latest) = latest_meta.as_ref() {
            if self
                .git_storage
                .fetch_pack_for_commit(workspace_id, latest.commit_id.as_slice())
                .await?
                .is_none()
            {
                // Try to restore metadata and pack from storage (if pointer mismatch), else try remote bootstrap.
                warn!(
                    workspace_id = %workspace_id,
                    commit = %encode_commit_id(&latest.commit_id),
                    "git_sync_missing_latest_pack_detected"
                );
                // Attempt backfill from storage; ensure_latest_meta will also update latest pointer.
                self.ensure_storage_commit_integrity(workspace_id).await?;
                latest_meta = self.ensure_latest_meta(workspace_id).await?;
                if let Some(latest2) = latest_meta.as_ref() {
                    if self
                        .git_storage
                        .fetch_pack_for_commit(workspace_id, latest2.commit_id.as_slice())
                        .await?
                        .is_none()
                    {
                        if let Some(cfg) = cfg {
                            if !cfg.repository_url.is_empty() {
                                info!(
                                    workspace_id = %workspace_id,
                                    commit = %encode_commit_id(&latest2.commit_id),
                                    "git_sync_missing_latest_pack_bootstrap_remote"
                                );
                                self.bootstrap_remote_history(
                                    workspace_id,
                                    cfg,
                                    branch_hint.as_str(),
                                )
                                .await?;
                                latest_meta = self.ensure_latest_meta(workspace_id).await?;
                            }
                        }
                    }
                }
                if let Some(latest3) = latest_meta.as_ref() {
                    if self
                        .git_storage
                        .fetch_pack_for_commit(workspace_id, latest3.commit_id.as_slice())
                        .await?
                        .is_none()
                    {
                        anyhow::bail!(
                            "missing pack data for latest commit {}; pull and retry",
                            encode_commit_id(&latest3.commit_id)
                        );
                    }
                }
            }
        }

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

        let use_full_scan = force_full_scan || latest_meta.is_none();

        let previous_index = latest_meta
            .as_ref()
            .map(|c| c.file_hash_index.clone())
            .unwrap_or_default();
        let dirty_rows = self.fetch_dirty(workspace_id).await?;

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

        // If still nothing to do, optionally push existing head when a remote is configured.
        if !use_full_scan && upserts.is_empty() && deletes.is_empty() {
            if push_required {
                if let Some(latest) = latest_meta.as_ref() {
                    // Ensure pack chain exists to materialize the commit for push.
                    let pack_chain = self
                        .persist_pack_chain(workspace_id, Some(latest.commit_id.as_slice()))
                        .await?;
                    if let Some((temp_dir, pack_paths)) = pack_chain {
                        let repo = Repository::init_bare(temp_dir.path())?;
                        apply_pack_files(&repo, &pack_paths)?;
                        let oid = git2::Oid::from_bytes(&latest.commit_id)?;
                        let pushed =
                            perform_push(&repo, cfg.unwrap(), &branch_name, oid, force_push)?;
                        drop(repo);
                        drop(temp_dir);
                        let _ = self.clear_dirty(workspace_id).await;
                        return Ok(GitSyncOutcome {
                            files_changed: 0,
                            commit_hash: Some(encode_commit_id(&latest.commit_id)),
                            pushed,
                            message: if pushed {
                                "push completed".to_string()
                            } else {
                                "nothing to push".to_string()
                            },
                        });
                    }
                }
            }
            // Nothing to commit/push: clear any leftover dirty and exit.
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
        let mut files_changed_for_response: u32;

        if use_full_scan {
            // Rebuild full-scan data fresh in case we fell back here after a pack failure.
            next_file_hash_index.clear();
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

        let mut previous_pack = None;
        if let Some(prev_meta) = latest_meta.as_ref() {
            let prev_commit_hex = encode_commit_id(&prev_meta.commit_id);
            match self
                .persist_pack_chain(workspace_id, Some(prev_meta.commit_id.as_slice()))
                .await?
            {
                Some(chain) => {
                    previous_pack = Some(chain);
                }
                None => {
                    // Attempt to repair from remote and retry once.
                    if let Some(cfg) = cfg {
                        if !cfg.repository_url.is_empty() {
                            warn!(
                                workspace_id = %workspace_id,
                                commit = %prev_commit_hex,
                                "git_sync_missing_pack_chain_recover"
                            );
                            self.recover_missing_objects(workspace_id, cfg).await?;
                            latest_meta = self.ensure_latest_meta(workspace_id).await?;
                            if let Some(latest) = latest_meta.as_ref() {
                                previous_pack = self
                                    .persist_pack_chain(
                                        workspace_id,
                                        Some(latest.commit_id.as_slice()),
                                    )
                                    .await?;
                            }
                        }
                    }
                    if previous_pack.is_none() {
                        warn!(
                            workspace_id = %workspace_id,
                            "git_sync_missing_pack_chain_abort"
                        );
                        anyhow::bail!(
                            "missing pack data for current head {}; pull/import required before sync",
                            prev_commit_hex
                        );
                    }
                }
            }
        }

        let (meta, pack_bytes, commit_hex, pushed) = {
            let temp_dir = TempDirBuilder::new()
                .prefix("git-sync-")
                .tempdir()
                .map_err(|e| anyhow::anyhow!(e))?;
            let repo = Repository::init_bare(temp_dir.path())?;

            if let Some((_, ref pack_paths)) = previous_pack {
                // Apply full chain to ensure delta bases are present
                if let Err(err) = apply_pack_files(&repo, pack_paths) {
                    let lower = err.to_string().to_lowercase();
                    let missing_obj = lower.contains("missing") && lower.contains("object");
                    if missing_obj {
                        // Try to repair packs by re-bootstrap from remote, then retry apply once more.
                        warn!(
                            workspace_id = %workspace_id,
                            error = %err,
                            "git_sync_pack_missing_objects_retry_bootstrap"
                        );
                        if let Some(cfg) = cfg {
                            if !cfg.repository_url.is_empty() {
                                let branch = branch_name.clone();
                                self.bootstrap_remote_history(workspace_id, cfg, branch.as_str())
                                    .await?;
                                previous_pack = self
                                    .persist_pack_chain(
                                        workspace_id,
                                        latest_meta.as_ref().map(|m| m.commit_id.as_slice()),
                                    )
                                    .await?;
                                if let Some((_, ref pack_paths_retry)) = previous_pack {
                                    if apply_pack_files(&repo, pack_paths_retry).is_err() {
                                        // Last resort: recover objects and retry once more.
                                        warn!(
                                            workspace_id = %workspace_id,
                                            "git_sync_pack_retry_still_missing_recovering_objects"
                                        );
                                        self.recover_missing_objects(workspace_id, cfg).await?;
                                        latest_meta = self.ensure_latest_meta(workspace_id).await?;
                                        previous_pack = self
                                            .persist_pack_chain(
                                                workspace_id,
                                                latest_meta
                                                    .as_ref()
                                                    .map(|m| m.commit_id.as_slice()),
                                            )
                                            .await?;
                                        if let Some((_, ref pack_paths_retry2)) = previous_pack {
                                            apply_pack_files(&repo, pack_paths_retry2)?;
                                        } else {
                                            anyhow::bail!(
                                                "missing pack objects after recovery; pull/import required before sync"
                                            );
                                        }
                                    }
                                } else {
                                    anyhow::bail!(
                                        "missing pack objects after bootstrap; pull/import required before sync"
                                    );
                                }
                            }
                        }
                        anyhow::bail!(
                            "missing pack objects for {}; pull/import to repair history",
                            latest_meta
                                .as_ref()
                                .map(|m| encode_commit_id(&m.commit_id))
                                .unwrap_or_else(|| "unknown".to_string())
                        );
                    } else {
                        return Err(err);
                    }
                }
            }

            // Skip pre-fetch/verify to avoid remote redirect/auth loops; rely on push outcome.
            // Build sources from either full scan or dirty set (no awaits here)
            let tree_oid = if use_full_scan {
                if precomputed_full_entries.is_none() {
                    // We fell back to full-scan after a pack failure; rebuild snapshots fresh.
                    next_file_hash_index.clear();
                    let current = self.collect_current_state(workspace_id).await?;
                    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
                    for (path, snapshot) in current.iter() {
                        let bytes = self.snapshot_bytes(snapshot).await?;
                        entries.insert(path.clone(), bytes);
                        next_file_hash_index.insert(path.clone(), snapshot.hash.clone());
                    }
                    files_changed_for_response = next_file_hash_index.len() as u32;
                    precomputed_full_entries = Some(entries);
                }
                let entries = precomputed_full_entries
                    .as_ref()
                    .ok_or_else(|| anyhow!("full-scan entries missing"))?;
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
            // Include parent commit objects to avoid missing bases when applying packs later.
            for parent in parent_commits.iter() {
                pack_builder.insert_commit(parent.id())?;
            }
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

            (meta, pack_bytes, commit_hex, pushed)
        };

        if let Some((dir, _)) = previous_pack {
            drop(dir);
        }

        // If push to a configured remote failed, do not advance local commit pointers or clear dirty state.
        // Leave files as-is so the next sync attempt will retry the push instead of treating the workspace as clean.
        if push_required && !pushed {
            return Ok(GitSyncOutcome {
                files_changed: files_changed_for_response,
                commit_hash: None,
                pushed: false,
                message: "commit created (push failed)".to_string(),
            });
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
        self.clear_dirty(workspace_id).await.map_err(|err| {
            error!(workspace_id = %workspace_id, error = %err, "git_import_clear_dirty_failed");
            err
        })?;
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

    async fn import_repository(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<GitImportOutcome> {
        // Suppress dirty tracking globally during import so filesystem watcher/ingest won't re-mark files.
        let _global_dirty_guard = crate::infrastructure::storage::suppress_git_dirty_global();
        let branch = if cfg.branch_name.is_empty() {
            "main".to_string()
        } else {
            cfg.branch_name.clone()
        };
        self.ensure_repository(workspace_id, &branch).await?;

        let previous_index = self
            .latest_commit_meta(workspace_id)
            .await?
            .map(|m| m.file_hash_index)
            .unwrap_or_default();

        // Populate storage and DB with remote history; surface errors so we don't proceed with missing packs.
        self.bootstrap_remote_history(workspace_id, cfg, branch.as_str())
            .await?;
        let latest = self.ensure_latest_meta(workspace_id).await?;
        let Some(latest_meta) = latest else {
            return Ok(GitImportOutcome {
                files_changed: 0,
                commit_hash: None,
                docs_created: 0,
                attachments_created: 0,
                message: "remote has no commits".to_string(),
            });
        };

        let state = self
            .state_from_commit_meta(workspace_id, &latest_meta)
            .await?;
        let files_changed = crate::infrastructure::storage::suppress_git_dirty(async {
            self.apply_state_to_workspace(workspace_id, &state, &previous_index)
                .await
        })
        .await?;

        // Materialize documents and attachments from imported state; surface failures so Import can fail loudly.
        let (docs_created, attachments_created) =
            crate::infrastructure::storage::suppress_git_dirty(async {
                self.materialize_documents_from_state(workspace_id, actor_id, &state)
                    .await
            })
            .await?;

        self.apply_merged_to_documents(workspace_id, &state).await?;
        self.clear_dirty(workspace_id).await.map_err(|err| {
            error!(workspace_id = %workspace_id, error = %err, "git_import_clear_dirty_failed");
            err
        })?;

        Ok(GitImportOutcome {
            files_changed,
            docs_created,
            attachments_created,
            commit_hash: Some(encode_commit_id(&latest_meta.commit_id)),
            message: "import completed".to_string(),
        })
    }

    async fn pull(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        req: &GitPullRequestDto,
        cfg: &UserGitCfg,
    ) -> anyhow::Result<GitPullResultDto> {
        let mut recover_attempts: u8 = 0;
        let mut skip_local_pack_restore = false;
        loop {
            match self
                .pull_once(workspace_id, actor_id, req, cfg, skip_local_pack_restore)
                .await
            {
                Ok(dto) => return Ok(dto),
                Err(err) => {
                    if Self::is_missing_objects(&err) {
                        if recover_attempts < 2 {
                            recover_attempts += 1;
                            skip_local_pack_restore = true;
                            warn!(
                                workspace_id = %workspace_id,
                                attempt = %recover_attempts,
                                error = %err,
                                "git_pull_missing_objects_recovering"
                            );
                            self.recover_missing_objects(workspace_id, cfg).await?;
                            continue;
                        }
                    }
                    return Err(err);
                }
            }
        }
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
    async fn build_conflict_item(
        &self,
        workspace_id: Uuid,
        path: &str,
        current_state: &HashMap<String, FileSnapshot>,
        remote_state: &HashMap<String, FileSnapshot>,
        local_meta: Option<&CommitMeta>,
    ) -> anyhow::Result<GitPullConflictItemDto> {
        let ours_bytes = if let Some(snap) = current_state.get(path) {
            Some(self.snapshot_bytes(snap).await?)
        } else {
            None
        };
        let theirs_bytes = if let Some(snap) = remote_state.get(path) {
            Some(self.snapshot_bytes(snap).await?)
        } else {
            Some(Vec::new())
        };
        let base_bytes = if let Some(meta) = local_meta.as_ref() {
            self.load_file_snapshot(workspace_id, meta.commit_id.as_slice(), path)
                .await?
        } else {
            None
        };

        let (mut ours, ours_bin) = as_text_or_binary(path, ours_bytes.as_ref());
        let (mut theirs, theirs_bin) = as_text_or_binary(path, theirs_bytes.as_ref());
        let (mut base, base_bin) = as_text_or_binary(path, base_bytes.as_ref());
        let is_binary = ours_bin || theirs_bin || base_bin;
        if !is_binary {
            ours = strip_front_matter_body(path, ours);
            theirs = strip_front_matter_body(path, theirs);
            base = strip_front_matter_body(path, base);
        }

        Ok(GitPullConflictItemDto {
            path: path.to_string(),
            is_binary,
            ours,
            theirs,
            base,
            document_id: None,
        })
    }

    async fn pull_once(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        req: &GitPullRequestDto,
        cfg: &UserGitCfg,
        skip_local_pack_restore: bool,
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

        // Capture current workspace head before touching remote history.
        let mut local_meta = self.latest_commit_meta(workspace_id).await?;
        // After a recovery we want to treat pull as a fresh fast-forward from remote.
        if skip_local_pack_restore {
            local_meta = None;
        }
        let mut local_history_reset = false;
        let mut base_index: HashMap<String, String> = local_meta
            .as_ref()
            .map(|m| m.file_hash_index.clone())
            .unwrap_or_default();
        let mut previous_index = base_index.clone();
        let mut base_commit = local_meta.as_ref().map(|m| m.commit_id.clone());

        let temp_dir = TempDirBuilder::new()
            .prefix("git-pull-")
            .tempdir()
            .map_err(|e| anyhow::anyhow!(e))?;
        let repo = Repository::init_bare(temp_dir.path())?;
        if !skip_local_pack_restore {
            match self
                .persist_pack_chain(
                    workspace_id,
                    local_meta.as_ref().map(|m| m.commit_id.as_slice()),
                )
                .await?
            {
                Some((_, pack_paths)) => {
                    apply_pack_files(&repo, &pack_paths)?;
                }
                None => {
                    warn!(
                        workspace_id = %workspace_id,
                        "git_pull_pack_restore_missing_resetting_base"
                    );
                    // Storage/DB history was reset; treat as fresh pull with no local history.
                    local_meta = None;
                    local_history_reset = true;
                    base_index.clear();
                    previous_index.clear();
                    base_commit = None;
                }
            }
        } else {
            info!(workspace_id = %workspace_id, "git_pull_skip_local_pack_restore");
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

        let mut local_oid = if local_history_reset {
            None
        } else {
            local_meta
                .as_ref()
                .and_then(|m| git2::Oid::from_bytes(&m.commit_id).ok())
        };
        // If workspace has no local commit recorded (fresh pull), fall back to latest known meta after bootstrap.
        if local_oid.is_none() && !skip_local_pack_restore && !local_history_reset {
            if let Some(meta) = self.latest_commit_meta(workspace_id).await? {
                base_index = meta.file_hash_index.clone();
                previous_index = base_index.clone();
                base_commit = Some(meta.commit_id.clone());
                local_oid = git2::Oid::from_bytes(&meta.commit_id).ok();
                local_meta = Some(meta);
            }
        }
        // Detect drift between latest commit and current workspace using the same dirty set as Git Changes/Status.
        let dirty_rows = self.fetch_dirty(workspace_id).await?;
        let current_state = self.collect_current_state(workspace_id).await?;
        info!(workspace_id = %workspace_id, dirty_count = dirty_rows.len(), skip_local_pack_restore = skip_local_pack_restore, "git_pull_dirty_state");

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum CommitRelation {
            NoLocal,
            Same,
            LocalAhead,
            RemoteAhead,
            Diverged,
        }

        let commit_relation = if let Some(local_oid_val) = local_oid {
            if local_oid_val == remote_oid {
                CommitRelation::Same
            } else if repo.graph_descendant_of(local_oid_val, remote_oid)? {
                CommitRelation::LocalAhead
            } else if repo.graph_descendant_of(remote_oid, local_oid_val)? {
                CommitRelation::RemoteAhead
            } else {
                CommitRelation::Diverged
            }
        } else {
            CommitRelation::NoLocal
        };

        // Nothing to do when remote is identical to or behind the local head.
        if matches!(
            commit_relation,
            CommitRelation::Same | CommitRelation::LocalAhead
        ) {
            let commit_hash = local_oid
                .as_ref()
                .map(|oid| encode_commit_id(oid.as_bytes()));
            return Ok(GitPullResultDto {
                success: true,
                message: "no remote changes".to_string(),
                files_changed: 0,
                commit_hash,
                conflicts: None,
                base_commit: base_commit.clone(),
                remote_commit: remote_commit.clone(),
            });
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
        let remote_changed_paths_vec: Vec<String> = remote_changed_paths.iter().cloned().collect();
        for path in remote_changed_paths_vec.iter() {
            let item = self
                .build_conflict_item(
                    workspace_id,
                    path,
                    &current_state,
                    &remote_state,
                    local_meta.as_ref(),
                )
                .await?;
            remote_conflicts.push(item);
        }

        // First-time pull with no local history and no dirty changes: allow fast-forward without forcing conflicts.
        if local_meta.is_none() && dirty_rows.is_empty() {
            remote_conflicts.clear();
        }

        // If commits differ but no conflict paths were detected above, fallback to diff of current vs remote trees.
        if remote_conflicts.is_empty() {
            let local_oid_val = local_oid.unwrap_or(remote_oid);
            if remote_oid != local_oid_val {
                let mut all_paths: HashSet<String> = HashSet::new();
                for p in remote_state.keys() {
                    all_paths.insert(p.clone());
                }
                for p in current_state.keys() {
                    all_paths.insert(p.clone());
                }
                for path in all_paths {
                    let remote_hash = remote_state.get(&path).map(|s| &s.hash);
                    let local_hash = current_state.get(&path).map(|s| &s.hash);
                    if remote_hash == local_hash {
                        continue;
                    }

                    let item = self
                        .build_conflict_item(
                            workspace_id,
                            &path,
                            &current_state,
                            &remote_state,
                            local_meta.as_ref(),
                        )
                        .await?;
                    remote_conflicts.push(item);
                }
            }
        }
        let remote_changes = !remote_conflicts.is_empty();
        let remote_ahead_clean =
            matches!(commit_relation, CommitRelation::RemoteAhead) && dirty_rows.is_empty();
        let fast_forward_remote =
            matches!(commit_relation, CommitRelation::NoLocal) || remote_ahead_clean;

        // Detect overlap between remote-changed paths and dirty rows to avoid false conflicts.
        let dirty_paths: HashSet<String> = dirty_rows.iter().map(|r| r.path.clone()).collect();
        let dirty_remote_overlap = remote_changed_paths_vec
            .iter()
            .any(|p| dirty_paths.contains(p));

        info!(
            workspace_id = %workspace_id,
            dirty_count = dirty_rows.len(),
            remote_conflict_count = remote_conflicts.len(),
            remote_changes = remote_changes,
            resolutions_count = req.resolutions.len(),
            dirty_remote_overlap = dirty_remote_overlap,
            "git_pull_debug_state"
        );

        // If workspace has dirty changes overlapping remote changes, require explicit resolutions.
        if remote_changes && dirty_remote_overlap && req.resolutions.is_empty() {
            let conflicts = if remote_conflicts.is_empty() {
                vec![GitPullConflictItemDto {
                    path: "".to_string(),
                    is_binary: false,
                    ours: None,
                    theirs: None,
                    base: None,
                    document_id: None,
                }]
            } else {
                remote_conflicts.clone()
            };
            return Ok(GitPullResultDto {
                success: false,
                message: "conflicts detected".to_string(),
                files_changed: 0,
                commit_hash: None,
                conflicts: Some(conflicts),
                base_commit: base_commit.clone(),
                remote_commit: remote_commit.clone(),
            });
        }

        // Ensure remote head commit metadata/pack exists locally for merge parent and future syncs.
        let mut remote_pack: Option<(CommitMeta, Vec<u8>)> = None;
        if self
            .commit_meta_by_id(workspace_id, remote_oid.as_bytes())
            .await?
            .is_none()
        {
            let remote_index: HashMap<String, String> = remote_state
                .iter()
                .map(|(path, snap)| (path.clone(), snap.hash.clone()))
                .collect();
            let (remote_meta, remote_pack_bytes) = {
                let remote_commit_obj = repo.find_commit(remote_oid)?;
                let committed_at = git_time_to_datetime(remote_commit_obj.time())?;
                let message = remote_commit_obj
                    .message()
                    .map(|m| m.trim_end_matches('\n').to_string())
                    .filter(|m| !m.trim().is_empty());
                let author = remote_commit_obj.author();
                let author_name = author.name().map(|s| s.to_string());
                let author_email = author.email().map(|s| s.to_string());
                let parent_commit_id = if remote_commit_obj.parent_count() > 0 {
                    let parent = remote_commit_obj.parent_id(0)?;
                    Some(parent.as_bytes().to_vec())
                } else {
                    None
                };

                let mut pack_builder = repo.packbuilder()?;
                pack_builder.insert_commit(remote_oid)?;
                if let Some(parent_id) = parent_commit_id.as_ref() {
                    if let Ok(parent_oid) = git2::Oid::from_bytes(parent_id) {
                        let _ = pack_builder.insert_commit(parent_oid);
                    }
                }
                let mut pack_buf = git2::Buf::new();
                pack_builder.write_buf(&mut pack_buf)?;
                let pack_bytes = pack_buf.to_vec();

                let commit_hex = encode_commit_id(remote_oid.as_bytes());
                let remote_meta = CommitMeta {
                    commit_id: remote_oid.as_bytes().to_vec(),
                    parent_commit_id,
                    message,
                    author_name,
                    author_email,
                    committed_at,
                    pack_key: format!("git/packs/{}/{}.pack", workspace_id, commit_hex),
                    file_hash_index: remote_index,
                };
                (remote_meta, pack_bytes)
            };
            remote_pack = Some((remote_meta, remote_pack_bytes));
        }

        // Fast-forward when there is no local history or the workspace head cleanly trails remote.
        // For fresh workspaces with dirty changes, surface conflicts instead of overwriting.
        if fast_forward_remote {
            if matches!(commit_relation, CommitRelation::NoLocal)
                && (!dirty_rows.is_empty() || !remote_conflicts.is_empty())
            {
                return Ok(GitPullResultDto {
                    success: false,
                    message: "conflicts detected".to_string(),
                    files_changed: 0,
                    commit_hash: None,
                    conflicts: Some(remote_conflicts.clone()),
                    base_commit: base_commit.clone(),
                    remote_commit: remote_commit.clone(),
                });
            }
            // Ensure we have pack data for the remote head regardless of existing metadata.
            let (remote_meta, remote_pack_bytes) = if let Some((meta, pack)) = remote_pack.take() {
                (meta, Some(pack))
            } else {
                let mut pack_builder = repo.packbuilder()?;
                pack_builder.insert_commit(remote_oid)?;
                // Include parent to avoid missing bases later.
                if let Ok(parent_id) = repo.find_commit(remote_oid).and_then(|c| c.parent_id(0)) {
                    let _ = pack_builder.insert_commit(parent_id);
                }
                let mut pack_buf = git2::Buf::new();
                pack_builder.write_buf(&mut pack_buf)?;
                let pack_bytes = pack_buf.to_vec();

                let remote_index: HashMap<String, String> = remote_state
                    .iter()
                    .map(|(p, snap)| (p.clone(), snap.hash.clone()))
                    .collect();
                let commit = repo.find_commit(remote_oid)?;
                let committed_at = git_time_to_datetime(commit.time())?;
                let message = commit
                    .message()
                    .map(|m| m.trim_end_matches('\n').to_string())
                    .filter(|m| !m.trim().is_empty());
                let author = commit.author();
                let author_name = author.name().map(|s| s.to_string());
                let author_email = author.email().map(|s| s.to_string());
                let parent_commit_id = if commit.parent_count() > 0 {
                    Some(commit.parent_id(0)?.as_bytes().to_vec())
                } else {
                    None
                };
                let commit_hex = encode_commit_id(remote_oid.as_bytes());
                let meta = CommitMeta {
                    commit_id: remote_oid.as_bytes().to_vec(),
                    parent_commit_id,
                    message,
                    author_name,
                    author_email,
                    committed_at,
                    pack_key: format!("git/packs/{}/{}.pack", workspace_id, commit_hex),
                    file_hash_index: remote_index,
                };
                (meta, Some(pack_bytes))
            };

            if let Some(pack_bytes) = remote_pack_bytes.as_ref() {
                self.git_storage
                    .store_pack(workspace_id, pack_bytes, &remote_meta)
                    .await?;
            }
            self.upsert_commit_record(workspace_id, &remote_meta)
                .await?;

            let snapshot_keys = self
                .store_commit_snapshots(workspace_id, &remote_meta.commit_id, &remote_state)
                .await?;

            if let Err(err) = self
                .git_storage
                .set_latest_commit(workspace_id, Some(&remote_meta))
                .await
            {
                for key in snapshot_keys.iter().rev() {
                    let _ = self.git_storage.delete_blob(key).await;
                }
                return Err(err);
            }

            let mut tx = self.pool.begin().await?;
            // Ensure repo row still exists and initialized.
            let repo_row =
                sqlx::query("SELECT initialized FROM git_repository_state WHERE workspace_id = $1")
                    .bind(workspace_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            let Some(repo_row) = repo_row else {
                tx.rollback().await.ok();
                anyhow::bail!("repository not initialized")
            };
            let initialized: bool = repo_row.get("initialized");
            if !initialized {
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
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                    ON CONFLICT (commit_id, workspace_id) DO NOTHING"#,
            )
            .bind(remote_meta.commit_id.clone())
            .bind(remote_meta.parent_commit_id.clone())
            .bind(workspace_id)
            .bind(remote_meta.message.clone())
            .bind(remote_meta.author_name.clone())
            .bind(remote_meta.author_email.clone())
            .bind(remote_meta.committed_at)
            .bind(remote_meta.pack_key.clone())
            .bind(Json(&remote_meta.file_hash_index))
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "UPDATE git_repository_state SET updated_at = now() WHERE workspace_id = $1",
            )
            .bind(workspace_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;

            let files_changed = self
                .apply_state_to_workspace(workspace_id, &remote_state, &previous_index)
                .await?;

            // Create any missing documents/attachments from the pulled state before syncing realtime.
            self.materialize_documents_from_state(workspace_id, actor_id, &remote_state)
                .await?;
            self.apply_merged_to_documents(workspace_id, &remote_state)
                .await?;
            self.clear_dirty(workspace_id).await.map_err(|err| {
                error!(workspace_id = %workspace_id, error = %err, "git_pull_clear_dirty_failed");
                err
            })?;

            info!(
                workspace_id = %workspace_id,
                commit = %encode_commit_id(&remote_meta.commit_id),
                "git_pull_fast_forward_remote"
            );

            return Ok(GitPullResultDto {
                success: true,
                message: "fast-forwarded to remote".to_string(),
                files_changed,
                commit_hash: Some(encode_commit_id(&remote_meta.commit_id)),
                conflicts: None,
                base_commit: base_commit.clone(),
                remote_commit: Some(remote_meta.commit_id.clone()),
            });
        }

        // Diverged: merge local into remote (linear, parent = remote)
        let Some(local_oid_val) = local_oid else {
            anyhow::bail!("no local commit to merge");
        };

        let (meta, pack_bytes, merged_snapshots, commit_hex) = {
            // Build a synthetic "ours" commit from the current workspace state anchored to the local head
            // so dirty edits participate in the merge against remote changes.
            let synthetic_ours = self.build_synthetic_commit(workspace_id, &repo, local_oid_val)?;
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
            let mut conflict_entries: Vec<(
                String,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
            )> = Vec::new();
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
            > = req
                .resolutions
                .iter()
                .map(|r| (r.path.clone(), r))
                .collect();

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
                    let (mut ours_txt, ours_bin) =
                        as_text_or_binary(path.as_str(), ours_bytes.as_ref());
                    let (mut theirs_txt, theirs_bin) =
                        as_text_or_binary(path.as_str(), theirs_bytes.as_ref());
                    let (mut base_txt, base_bin) =
                        as_text_or_binary(path.as_str(), base_bytes.as_ref());
                    let is_binary = ours_bin || theirs_bin || base_bin;
                    if !is_binary {
                        ours_txt = strip_front_matter_body(path.as_str(), ours_txt);
                        theirs_txt = strip_front_matter_body(path.as_str(), theirs_txt);
                        base_txt = strip_front_matter_body(path.as_str(), base_txt);
                    }
                    unresolved.push(GitPullConflictItemDto {
                        path: path.clone(),
                        is_binary,
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
                        let content = res
                            .content
                            .as_ref()
                            .ok_or_else(|| anyhow!("custom_text content required"))?;
                        Some(content.as_bytes().to_vec())
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
            let base_parent = repo.find_commit(local_oid_val)?;
            let remote_parent = repo.find_commit(remote_oid)?;
            let parent_refs: [&git2::Commit; 2] = [&base_parent, &remote_parent];
            let commit_oid = repo.commit(
                None,
                &sig,
                &sig,
                "Merge remote changes",
                &tree,
                &parent_refs,
            )?;

            let mut file_hash_index: HashMap<String, String> = HashMap::new();
            for (path, snap) in merged_snapshots.iter() {
                file_hash_index.insert(path.clone(), snap.hash.clone());
            }

            let mut pack_builder = repo.packbuilder()?;
            pack_builder.insert_commit(commit_oid)?;
            // Include both parents to avoid missing bases when applying packs later.
            pack_builder.insert_commit(base_parent.id())?;
            pack_builder.insert_commit(remote_parent.id())?;
            let mut pack_buf = git2::Buf::new();
            pack_builder.write_buf(&mut pack_buf)?;
            let pack_bytes = pack_buf.to_vec();

            let commit_hex = encode_commit_id(commit_oid.as_bytes());
            let meta = CommitMeta {
                commit_id: commit_oid.as_bytes().to_vec(),
                // Keep workspace history linear: parent is previous workspace head.
                parent_commit_id: base_commit.clone(),
                message: Some("Merge remote changes".to_string()),
                author_name: Some("RefMD".to_string()),
                author_email: Some("refmd@example.com".to_string()),
                committed_at: chrono::Utc::now(),
                pack_key: format!("git/packs/{}/{}.pack", workspace_id, commit_hex),
                file_hash_index,
            };

            (meta, pack_bytes, merged_snapshots, commit_hex)
        };

        // Persist remote parent if we created it above.
        if let Some((remote_meta, remote_pack_bytes)) = remote_pack.take() {
            self.git_storage
                .store_pack(workspace_id, &remote_pack_bytes, &remote_meta)
                .await?;
            self.upsert_commit_record(workspace_id, &remote_meta)
                .await?;
        }

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

        // Create any missing documents/attachments from the merged state before syncing realtime.
        self.materialize_documents_from_state(workspace_id, actor_id, &merged_snapshots)
            .await?;
        // Apply merged markdown back into realtime/doc storage immediately.
        self.apply_merged_to_documents(workspace_id, &merged_snapshots)
            .await?;

        self.clear_dirty(workspace_id).await.map_err(|err| {
            error!(workspace_id = %workspace_id, error = %err, "git_pull_merge_clear_dirty_failed");
            err
        })?;

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

    async fn persist_pack_chain(
        &self,
        workspace_id: Uuid,
        until: Option<&[u8]>,
    ) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
        // Attempt to rebuild pack chain from stored snapshots if packs are missing or corrupted.
        async fn rebuild_from_snapshots(
            svc: &GitWorkspaceService,
            workspace_id: Uuid,
            until: Option<&[u8]>,
        ) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
            // Collect commit metas from oldest to newest
            let mut chain: Vec<CommitMeta> = Vec::new();
            let mut cursor = match until {
                Some(id) => svc.commit_meta_by_id(workspace_id, id).await?,
                None => svc.latest_commit_meta(workspace_id).await?,
            };
            while let Some(meta) = cursor {
                chain.push(meta.clone());
                if let Some(parent) = meta.parent_commit_id.as_ref() {
                    cursor = svc.commit_meta_by_id(workspace_id, parent).await?;
                } else {
                    break;
                }
            }
            if chain.is_empty() {
                return Ok(None);
            }
            chain.reverse();

            // Preload snapshots async
            let mut prepared: Vec<(CommitMeta, Vec<(String, Vec<u8>)>)> = Vec::new();
            for meta in chain.iter() {
                let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
                for path in meta.file_hash_index.keys() {
                    let Some(bytes) = svc
                        .load_file_snapshot(workspace_id, meta.commit_id.as_slice(), path)
                        .await?
                    else {
                        anyhow::bail!(
                            "missing snapshot blob for {} at commit {}",
                            path,
                            encode_commit_id(&meta.commit_id)
                        );
                    };
                    entries.push((path.clone(), bytes));
                }
                prepared.push((meta.clone(), entries));
            }

            // Build packs synchronously to avoid Send issues with git2 types
            let (temp_dir, pack_paths) = tokio::task::block_in_place(|| -> anyhow::Result<_> {
                let temp_dir = tempfile::tempdir()?;
                let repo = Repository::init_bare(temp_dir.path())?;
                let mut built_commits: HashMap<Vec<u8>, git2::Oid> = HashMap::new();
                let mut pack_paths: Vec<PathBuf> = Vec::new();

                for (meta, entries) in prepared.into_iter() {
                    let mut builder = repo.treebuilder(None)?;
                    for (path, bytes) in entries.iter() {
                        let blob_oid = repo.blob(bytes)?;
                        builder.insert(path, blob_oid, FileMode::Blob.into())?;
                    }
                    let tree_oid = builder.write()?;
                    let tree = repo.find_tree(tree_oid)?;

                    let sig = signature_from_parts(
                        meta.author_name.as_deref().unwrap_or("RefMD"),
                        meta.author_email.as_deref().unwrap_or("refmd@example.com"),
                        meta.committed_at,
                    )?;
                    let mut parents = Vec::new();
                    if let Some(parent) = meta.parent_commit_id.as_ref() {
                        if let Some(existing) = built_commits.get(parent) {
                            parents.push(repo.find_commit(*existing)?);
                        }
                    }
                    let parent_refs: Vec<&Commit> = parents.iter().collect();
                    let commit_oid = repo.commit(
                        None,
                        &sig,
                        &sig,
                        meta.message
                            .as_deref()
                            .unwrap_or("Recovered commit from snapshots"),
                        &tree,
                        &parent_refs,
                    )?;
                    if commit_oid.as_bytes() != meta.commit_id.as_slice() {
                        anyhow::bail!(
                            "reconstructed commit id mismatch for {}",
                            encode_commit_id(&meta.commit_id)
                        );
                    }
                    built_commits.insert(meta.commit_id.clone(), commit_oid);

                    let mut pack_builder = repo.packbuilder()?;
                    pack_builder.insert_commit(commit_oid)?;
                    for p in parents.iter() {
                        pack_builder.insert_commit(p.id())?;
                    }
                    let mut pack_buf = git2::Buf::new();
                    pack_builder.write_buf(&mut pack_buf)?;
                    let pack_bytes = pack_buf.to_vec();

                    let pack_path = temp_dir
                        .path()
                        .join(format!("{:08}.pack", pack_paths.len()));
                    std::fs::write(&pack_path, &pack_bytes)?;
                    pack_paths.push(pack_path);
                }

                Ok((temp_dir, pack_paths))
            })?;

            // Persist rebuilt packs and metas back to storage
            for (idx, meta) in chain.iter().enumerate() {
                let pack_bytes = std::fs::read(&pack_paths[idx])?;
                svc.git_storage
                    .store_pack(workspace_id, &pack_bytes, meta)
                    .await?;
                svc.upsert_commit_record(workspace_id, meta).await?;
                let _ = svc
                    .git_storage
                    .set_latest_commit(workspace_id, Some(meta))
                    .await;
            }

            Ok(Some((temp_dir, pack_paths)))
        }

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
                    let err_str = err.to_string();
                    let is_missing_objects = err_str.to_lowercase().contains("missing")
                        && err_str.to_lowercase().contains("object");
                    if let Some(rebuilt) = rebuild_from_snapshots(self, workspace_id, until).await?
                    {
                        return Ok(Some(rebuilt));
                    }
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
                        // If pack is missing objects, fall back by resetting git storage pointer and DB history.
                        if is_missing_objects {
                            warn!(
                                workspace_id = %workspace_id,
                                error = %err,
                                "git_pack_missing_objects_detected_resetting_history"
                            );
                            // Drop storage latest pointer and DB commits for this workspace.
                            let _ = self.git_storage.set_latest_commit(workspace_id, None).await;
                            let _ = sqlx::query("DELETE FROM git_commits WHERE workspace_id = $1")
                                .bind(workspace_id)
                                .execute(&self.pool)
                                .await;
                            return Ok(None);
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

fn read_first_pack(repo_path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    let pack_dir = repo_path.join("objects").join("pack");
    if !pack_dir.exists() {
        return Ok(None);
    }
    let mut entries: Vec<_> = std::fs::read_dir(&pack_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "pack")
                .unwrap_or(false)
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());
    if let Some(entry) = entries.first() {
        let bytes = std::fs::read(entry.path())?;
        return Ok(Some(bytes));
    }
    Ok(None)
}

fn find_front_matter_end(s: &str) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] == b'\n' {
            let after_newline = &s[idx + 1..];
            if after_newline.starts_with("---") {
                let mut body_start = idx + 1 + 3;
                let mut remainder = &s[body_start..];
                // Skip trailing newlines after the closing delimiter to mirror ingest.
                while remainder.starts_with("\r\n") || remainder.starts_with('\n') {
                    if remainder.starts_with("\r\n") {
                        body_start += 2;
                        remainder = &s[body_start..];
                    } else {
                        body_start += 1;
                        remainder = &s[body_start..];
                    }
                }
                return Some((idx, body_start));
            }
        }
        idx += 1;
    }
    None
}

fn split_front_matter(input: &str) -> Option<(&str, &str)> {
    let Some(after_open) = input
        .strip_prefix("---\r\n")
        .or_else(|| input.strip_prefix("---\n"))
    else {
        return None;
    };
    if let Some((front_len, body_start)) = find_front_matter_end(after_open) {
        let front = &after_open[..front_len];
        let body = &after_open[body_start..];
        return Some((front, body));
    }
    None
}

fn strip_front_matter_body(path: &str, text: Option<String>) -> Option<String> {
    let Some(txt) = text else {
        return None;
    };
    let lower = path.to_ascii_lowercase();
    let is_markdown = lower.ends_with(".md") || lower.ends_with(".markdown");
    if !is_markdown {
        return Some(txt);
    }
    if let Some((_, body)) = split_front_matter(txt.as_str()) {
        return Some(body.to_string());
    }
    Some(txt)
}

fn extract_markdown_body(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let trimmed = text.trim_start_matches('\u{feff}');
    if let Some((_, body)) = split_front_matter(trimmed) {
        return Some(body.to_string());
    }
    Some(trimmed.to_string())
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

        let (mut ours, ours_bin) = as_text_or_binary(path.as_str(), ours_bytes.as_ref());
        let (mut theirs, theirs_bin) = as_text_or_binary(path.as_str(), theirs_bytes.as_ref());
        let (mut base, base_bin) = as_text_or_binary(path.as_str(), base_bytes.as_ref());
        let is_binary = ours_bin || theirs_bin || base_bin;
        if !is_binary {
            ours = strip_front_matter_body(path.as_str(), ours);
            theirs = strip_front_matter_body(path.as_str(), theirs);
            base = strip_front_matter_body(path.as_str(), base);
        }

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
        Ok(String::from_utf8_lossy(raw)
            .trim_end_matches('\0')
            .to_string())
    }
}

fn index_entry_stage(entry: &git2::IndexEntry) -> i32 {
    ((entry.flags as u32 >> 12) & 0b11) as i32
}

fn as_text_or_binary(path: &str, data: Option<&Vec<u8>>) -> (Option<String>, bool) {
    let Some(bytes) = data else {
        return (None, false);
    };
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
        trimmed
            .replace('\\', "/")
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_string()
    }
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
