use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use git2::{
    CertificateCheckStatus, Commit, Cred, FetchOptions, FileMode, Indexer, ObjectType, PushOptions,
    RemoteCallbacks, Repository, Signature, Time, TreeWalkMode, TreeWalkResult,
};
use similar::{Algorithm, ChangeTag, TextDiff};
use sqlx::{Row, types::Json};
use tempfile::{Builder as TempDirBuilder, TempDir};
use tracing::warn;
use uuid::Uuid;

use crate::application::dto::git::{
    DiffLine, DiffLineType, DiffResult, GitChangeItem, GitCommitInfo, GitSyncOutcome,
    GitSyncRequestDto, GitWorkspaceStatus,
};
use crate::application::ports::git_repository::UserGitCfg;
use crate::application::ports::git_storage::{BlobKey, CommitMeta, GitStorage, encode_commit_id};
use crate::application::ports::git_workspace::GitWorkspacePort;
use crate::application::ports::storage_port::StoragePort;
use crate::infrastructure::db::PgPool;

pub struct GitWorkspaceService {
    pool: PgPool,
    git_storage: Arc<dyn GitStorage>,
    storage: Arc<dyn StoragePort>,
}

impl GitWorkspaceService {
    pub fn new(
        pool: PgPool,
        git_storage: Arc<dyn GitStorage>,
        storage: Arc<dyn StoragePort>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            pool,
            git_storage,
            storage,
        })
    }

    async fn load_repository_state(&self, user_id: Uuid) -> anyhow::Result<Option<(bool, String)>> {
        let row = sqlx::query(
            "SELECT initialized, default_branch FROM git_repository_state WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| (r.get("initialized"), r.get("default_branch"))))
    }

    async fn latest_commit_meta(&self, user_id: Uuid) -> anyhow::Result<Option<CommitMeta>> {
        let row = sqlx::query(
            r#"SELECT commit_id, parent_commit_id, message, author_name, author_email,
                      committed_at, pack_key, file_hash_index
               FROM git_commits
               WHERE user_id = $1
               ORDER BY committed_at DESC
               LIMIT 1"#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| row_to_commit_meta(r)).transpose()
    }

    async fn load_commit_meta_ref(
        &self,
        user_id: Uuid,
        rev: &str,
    ) -> anyhow::Result<Option<CommitMeta>> {
        if let Some(base) = rev.strip_suffix('^') {
            let Some(meta) = self.commit_meta_by_hex(user_id, base).await? else {
                return Ok(None);
            };
            if let Some(parent_id) = meta.parent_commit_id.clone() {
                return self.commit_meta_by_id(user_id, parent_id.as_slice()).await;
            }
            return Ok(None);
        }
        self.commit_meta_by_hex(user_id, rev).await
    }

    async fn commit_meta_by_id(
        &self,
        user_id: Uuid,
        commit_id: &[u8],
    ) -> anyhow::Result<Option<CommitMeta>> {
        let row = sqlx::query(
            r#"SELECT commit_id, parent_commit_id, message, author_name, author_email,
                      committed_at, pack_key, file_hash_index
               FROM git_commits
               WHERE user_id = $1 AND commit_id = $2
               LIMIT 1"#,
        )
        .bind(user_id)
        .bind(commit_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| row_to_commit_meta(row)).transpose()
    }

    async fn commit_meta_by_hex(
        &self,
        user_id: Uuid,
        hex: &str,
    ) -> anyhow::Result<Option<CommitMeta>> {
        let bytes = crate::application::ports::git_storage::decode_commit_id(hex)?;
        let row = sqlx::query(
            r#"SELECT commit_id, parent_commit_id, message, author_name, author_email,
                      committed_at, pack_key, file_hash_index
               FROM git_commits
               WHERE user_id = $1 AND commit_id = $2
               LIMIT 1"#,
        )
        .bind(user_id)
        .bind(bytes)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| row_to_commit_meta(r)).transpose()
    }

    async fn ensure_latest_meta(&self, user_id: Uuid) -> anyhow::Result<Option<CommitMeta>> {
        if let Some(meta) = self.latest_commit_meta(user_id).await? {
            return Ok(Some(meta));
        }
        let Some(storage_latest) = self.git_storage.latest_commit(user_id).await? else {
            return Ok(None);
        };
        self.backfill_commits_from_storage(user_id, &storage_latest)
            .await?;
        Ok(Some(storage_latest))
    }

    async fn backfill_commits_from_storage(
        &self,
        user_id: Uuid,
        latest: &CommitMeta,
    ) -> anyhow::Result<()> {
        let mut pending = Vec::new();
        let mut cursor = Some(latest.clone());
        while let Some(meta) = cursor {
            if self
                .commit_meta_by_id(user_id, meta.commit_id.as_slice())
                .await?
                .is_some()
            {
                break;
            }
            pending.push(meta.clone());
            cursor = match meta.parent_commit_id.clone() {
                Some(parent) => {
                    self.git_storage
                        .commit_meta(user_id, parent.as_slice())
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
                        user_id,
                        message,
                        author_name,
                        author_email,
                        committed_at,
                        pack_key,
                        file_hash_index
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                    ON CONFLICT (commit_id) DO NOTHING"#,
            )
            .bind(meta.commit_id.clone())
            .bind(meta.parent_commit_id.clone())
            .bind(user_id)
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

    async fn collect_current_state(
        &self,
        user_id: Uuid,
    ) -> anyhow::Result<HashMap<String, FileSnapshot>> {
        let mut state: HashMap<String, FileSnapshot> = HashMap::new();

        let doc_rows =
            sqlx::query("SELECT id FROM documents WHERE owner_id = $1 AND type <> 'folder'")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await?;

        for row in doc_rows {
            let doc_id: Uuid = row.get("id");
            let path = self.storage.build_doc_file_path(doc_id).await?;
            let bytes = match self.storage.read_bytes(path.as_path()).await {
                Ok(bytes) => bytes,
                Err(err) => {
                    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                        if io_err.kind() == std::io::ErrorKind::NotFound {
                            continue;
                        }
                    }
                    if err.to_string().contains("not found") {
                        continue;
                    }
                    return Err(err);
                }
            };
            let hash = sha256_hex(&bytes);
            let relative = self.storage.relative_from_uploads(path.as_path());
            let repo_path = repo_relative_path(&relative)?;
            state.insert(
                repo_path,
                FileSnapshot {
                    hash,
                    data: FileSnapshotData::Inline(bytes),
                    is_text: true,
                },
            );
        }

        let attachment_rows = sqlx::query(
            r#"SELECT f.storage_path, f.content_hash
               FROM files f
               JOIN documents d ON d.id = f.document_id
               WHERE d.owner_id = $1"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        for row in attachment_rows {
            let storage_path: String = row.get("storage_path");
            let hash: String = row.get("content_hash");
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
        user_id: Uuid,
        commit_id: &[u8],
        state: &HashMap<String, FileSnapshot>,
    ) -> anyhow::Result<Vec<BlobKey>> {
        let mut stored = Vec::new();
        for (path, snapshot) in state.iter() {
            let key = blob_key(user_id, commit_id, path);
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
        user_id: Uuid,
        commit_id: &[u8],
        path: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let key = blob_key(user_id, commit_id, path);
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

    fn build_diff_result(
        &self,
        path: &str,
        old_content: Option<&str>,
        new_content: Option<&str>,
    ) -> DiffResult {
        match (old_content, new_content) {
            (Some(old), Some(new)) => {
                let diff = TextDiff::configure()
                    .algorithm(Algorithm::Myers)
                    .diff_lines(old, new);
                let mut lines = Vec::new();
                let mut old_line = 0u32;
                let mut new_line = 0u32;
                for op in diff.ops() {
                    for change in diff.iter_changes(op) {
                        match change.tag() {
                            ChangeTag::Delete => {
                                old_line += 1;
                                lines.push(DiffLine {
                                    line_type: DiffLineType::Deleted,
                                    old_line_number: Some(old_line),
                                    new_line_number: None,
                                    content: change.to_string().trim_end().to_string(),
                                });
                            }
                            ChangeTag::Insert => {
                                new_line += 1;
                                lines.push(DiffLine {
                                    line_type: DiffLineType::Added,
                                    old_line_number: None,
                                    new_line_number: Some(new_line),
                                    content: change.to_string().trim_end().to_string(),
                                });
                            }
                            ChangeTag::Equal => {
                                old_line += 1;
                                new_line += 1;
                                lines.push(DiffLine {
                                    line_type: DiffLineType::Context,
                                    old_line_number: Some(old_line),
                                    new_line_number: Some(new_line),
                                    content: change.to_string().trim_end().to_string(),
                                });
                            }
                        }
                    }
                }
                DiffResult {
                    file_path: path.to_string(),
                    diff_lines: lines,
                    old_content: Some(old.to_string()),
                    new_content: Some(new.to_string()),
                }
            }
            _ => DiffResult {
                file_path: path.to_string(),
                diff_lines: Vec::new(),
                old_content: old_content.map(|s| s.to_string()),
                new_content: new_content.map(|s| s.to_string()),
            },
        }
    }

    async fn commit_diff_via_packs(
        &self,
        user_id: Uuid,
        from_meta: Option<&CommitMeta>,
        to_meta: &CommitMeta,
    ) -> anyhow::Result<Vec<DiffResult>> {
        let (to_pack_dir, to_pack_paths) = persist_pack_chain(
            self.git_storage.as_ref(),
            user_id,
            Some(to_meta.commit_id.as_slice()),
        )
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
                    persist_pack_chain(
                        self.git_storage.as_ref(),
                        user_id,
                        Some(from_meta.commit_id.as_slice()),
                    )
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
        user_id: Uuid,
        from_meta: Option<&CommitMeta>,
        to_meta: Option<&CommitMeta>,
    ) -> anyhow::Result<Vec<DiffResult>> {
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
                    self.load_file_snapshot(user_id, meta.commit_id.as_slice(), &path)
                        .await?
                }
                _ => None,
            };
            let new_bytes = match new_hash {
                Some(_) => {
                    self.load_file_snapshot(user_id, to_meta.commit_id.as_slice(), &path)
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
    async fn ensure_repository(&self, user_id: Uuid, default_branch: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO git_repository_state (user_id, initialized, default_branch, initialized_at, updated_at)
               VALUES ($1, true, $2, now(), now())
               ON CONFLICT (user_id) DO UPDATE SET
                 initialized = true,
                 default_branch = EXCLUDED.default_branch,
                 initialized_at = COALESCE(git_repository_state.initialized_at, EXCLUDED.initialized_at),
                 updated_at = now()"#,
        )
        .bind(user_id)
        .bind(default_branch)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_repository(&self, user_id: Uuid) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM git_commits WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE git_repository_state SET initialized = false, updated_at = now() WHERE user_id = $1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.git_storage.delete_all(user_id).await?;
        Ok(())
    }

    async fn status(&self, user_id: Uuid) -> anyhow::Result<GitWorkspaceStatus> {
        let state = self.load_repository_state(user_id).await?;
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
        let latest = self.latest_commit_meta(user_id).await?;
        let previous_index = latest
            .as_ref()
            .map(|c| c.file_hash_index.clone())
            .unwrap_or_default();
        let current = self.collect_current_state(user_id).await?;
        let delta = self.compute_deltas(&current, &previous_index);
        Ok(GitWorkspaceStatus {
            repository_initialized: true,
            current_branch: Some(branch),
            uncommitted_changes: (delta.modified.len() + delta.deleted.len()) as u32,
            untracked_files: delta.added.len() as u32,
        })
    }

    async fn list_changes(&self, user_id: Uuid) -> anyhow::Result<Vec<GitChangeItem>> {
        let latest = self.latest_commit_meta(user_id).await?;
        let previous_index = latest
            .as_ref()
            .map(|c| c.file_hash_index.clone())
            .unwrap_or_default();
        let current = self.collect_current_state(user_id).await?;
        let delta = self.compute_deltas(&current, &previous_index);
        let mut changes = Vec::new();
        for path in delta.added {
            changes.push(GitChangeItem {
                path,
                status: "untracked".to_string(),
            });
        }
        for path in delta.modified {
            changes.push(GitChangeItem {
                path,
                status: "modified".to_string(),
            });
        }
        for path in delta.deleted {
            changes.push(GitChangeItem {
                path,
                status: "deleted".to_string(),
            });
        }
        Ok(changes)
    }

    async fn working_diff(&self, user_id: Uuid) -> anyhow::Result<Vec<DiffResult>> {
        let latest = self.latest_commit_meta(user_id).await?;
        let previous_index = latest
            .as_ref()
            .map(|c| c.file_hash_index.clone())
            .unwrap_or_default();
        let current = self.collect_current_state(user_id).await?;
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
                            self.load_file_snapshot(user_id, commit_id.as_slice(), path)
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
                    results.push(DiffResult {
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
                self.load_file_snapshot(user_id, commit_id.as_slice(), &path)
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
        user_id: Uuid,
        from: &str,
        to: &str,
    ) -> anyhow::Result<Vec<DiffResult>> {
        let from_meta = self.load_commit_meta_ref(user_id, from).await?;
        let to_meta = self.load_commit_meta_ref(user_id, to).await?;

        if let Some(to_meta_ref) = to_meta.as_ref() {
            match self
                .commit_diff_via_packs(user_id, from_meta.as_ref(), to_meta_ref)
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

        self.commit_diff_from_storage(user_id, from_meta.as_ref(), to_meta.as_ref())
            .await
    }

    async fn history(&self, user_id: Uuid) -> anyhow::Result<Vec<GitCommitInfo>> {
        let rows = sqlx::query(
            r#"SELECT commit_id, message, author_name, author_email, committed_at
               FROM git_commits
               WHERE user_id = $1
               ORDER BY committed_at DESC
               LIMIT 200"#,
        )
        .bind(user_id)
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
        user_id: Uuid,
        req: &GitSyncRequestDto,
        cfg: Option<&UserGitCfg>,
    ) -> anyhow::Result<GitSyncOutcome> {
        let mut tx = self.pool.begin().await?;
        let repo_row = sqlx::query(
            "SELECT initialized, default_branch FROM git_repository_state WHERE user_id = $1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(repo_row) = repo_row else {
            tx.rollback().await.ok();
            anyhow::bail!("repository not initialized")
        };
        let initialized: bool = repo_row.get("initialized");
        let default_branch: String = repo_row.get("default_branch");
        let branch_name = cfg
            .map(|c| c.branch_name.clone())
            .unwrap_or(default_branch.clone());
        if !initialized {
            tx.rollback().await.ok();
            anyhow::bail!("repository not initialized")
        }

        let latest_meta = self.ensure_latest_meta(user_id).await?;

        let storage_latest = self.git_storage.latest_commit(user_id).await?;
        let storage_commit_hex = storage_latest
            .as_ref()
            .map(|m| encode_commit_id(&m.commit_id));
        let db_commit_hex = latest_meta.as_ref().map(|m| encode_commit_id(&m.commit_id));
        if storage_commit_hex != db_commit_hex {
            tx.rollback().await.ok();
            anyhow::bail!(
                "repository latest commit mismatch between database ({db_commit_hex:?}) and storage ({storage_commit_hex:?})"
            );
        }

        let previous_index = latest_meta
            .as_ref()
            .map(|c| c.file_hash_index.clone())
            .unwrap_or_default();
        let current = self.collect_current_state(user_id).await?;
        let delta = self.compute_deltas(&current, &previous_index);
        if delta.added.is_empty() && delta.modified.is_empty() && delta.deleted.is_empty() {
            tx.commit().await?;
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

        let files_changed = (delta.added.len() + delta.modified.len() + delta.deleted.len()) as u32;

        let previous_pack = if let Some(prev_meta) = latest_meta.as_ref() {
            Some(
                persist_pack_chain(
                    self.git_storage.as_ref(),
                    user_id,
                    Some(prev_meta.commit_id.as_slice()),
                )
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

        let (meta, pack_bytes, commit_hex, pushed) = {
            let temp_dir = TempDirBuilder::new()
                .prefix("git-sync-")
                .tempdir()
                .map_err(|e| anyhow::anyhow!(e))?;
            let repo = Repository::init_bare(temp_dir.path())?;

            if let Some((_, ref pack_paths)) = previous_pack {
                apply_pack_files(&repo, pack_paths)?;
            }

            if let Some(cfg) = cfg {
                if !cfg.repository_url.is_empty() {
                    fetch_remote_and_verify(
                        &repo,
                        cfg,
                        branch_name.as_str(),
                        latest_meta.as_ref(),
                    )?;
                }
            }

            let mut changed_paths: HashSet<String> = delta.added.iter().cloned().collect();
            changed_paths.extend(delta.modified.iter().cloned());

            let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            for (path, snapshot) in current.iter() {
                let needs_fresh_bytes = latest_meta.is_none() || changed_paths.contains(path);
                let bytes = if needs_fresh_bytes {
                    self.snapshot_bytes(snapshot).await?
                } else if let Some(prev_meta) = latest_meta.as_ref() {
                    match self
                        .load_file_snapshot(user_id, prev_meta.commit_id.as_slice(), path)
                        .await?
                    {
                        Some(data) => data,
                        None => self.snapshot_bytes(snapshot).await?,
                    }
                } else {
                    self.snapshot_bytes(snapshot).await?
                };
                entries.insert(path.clone(), bytes);
            }

            let tree_oid = build_tree_from_entries(&repo, &entries)?;
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

            let mut file_hash_index: HashMap<String, String> = HashMap::new();
            for (path, snapshot) in current.iter() {
                file_hash_index.insert(path.clone(), snapshot.hash.clone());
            }

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
                pack_key: format!("git/packs/{}/{}.pack", user_id, commit_hex.clone()),
                file_hash_index,
            };

            let mut pushed = false;
            if let Some(cfg) = cfg {
                if !cfg.repository_url.is_empty() {
                    pushed = perform_push(&repo, cfg, &branch_name, commit_oid)?;
                }
            }

            drop(repo);
            let _ = temp_dir.close();

            (meta, pack_bytes, commit_hex, pushed)
        };

        if let Some((dir, _)) = previous_pack {
            drop(dir);
        }

        sqlx::query(
            r#"INSERT INTO git_commits (
                    commit_id,
                    parent_commit_id,
                    user_id,
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
        .bind(user_id)
        .bind(meta.message.clone())
        .bind(meta.author_name.clone())
        .bind(meta.author_email.clone())
        .bind(meta.committed_at)
        .bind(meta.pack_key.clone())
        .bind(Json(&meta.file_hash_index))
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE git_repository_state SET updated_at = now() WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        let snapshot_keys = match self
            .store_commit_snapshots(user_id, &meta.commit_id, &current)
            .await
        {
            Ok(keys) => keys,
            Err(err) => {
                tx.rollback().await.ok();
                return Err(err);
            }
        };

        if let Err(err) = self
            .git_storage
            .store_pack(user_id, &pack_bytes, &meta)
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
            .set_latest_commit(user_id, Some(&meta))
            .await
        {
            let _ = self.git_storage.delete_pack(user_id, &meta.commit_id).await;
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            tx.rollback().await.ok();
            return Err(err);
        }

        if let Err(err) = tx.commit().await {
            let _ = self.git_storage.delete_pack(user_id, &meta.commit_id).await;
            for key in snapshot_keys.iter().rev() {
                let _ = self.git_storage.delete_blob(key).await;
            }
            let _ = self
                .git_storage
                .set_latest_commit(user_id, latest_meta.as_ref())
                .await;
            return Err(err.into());
        }
        Ok(GitSyncOutcome {
            files_changed,
            commit_hash: Some(commit_hex),
            pushed,
            message: if pushed {
                "sync completed".to_string()
            } else {
                "commit created".to_string()
            },
        })
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

async fn persist_pack_chain(
    storage: &dyn GitStorage,
    user_id: Uuid,
    until: Option<&[u8]>,
) -> anyhow::Result<Option<(TempDir, Vec<PathBuf>)>> {
    let mut stream = storage.load_pack_chain(user_id, until).await?;
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
        Ok(None)
    } else {
        Ok(Some((temp_dir, pack_paths)))
    }
}

fn apply_pack_files(repo: &Repository, pack_paths: &[PathBuf]) -> anyhow::Result<()> {
    for path in pack_paths {
        let bytes = fs::read(path)?;
        apply_pack_to_repo(repo, &bytes)?;
    }
    Ok(())
}

fn build_remote_callbacks(cfg: &UserGitCfg) -> RemoteCallbacks<'static> {
    let auth_type = cfg.auth_type.clone().unwrap_or_default();
    let auth_data = cfg.auth_data.clone();
    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(
        move |_url, username_from_url, _allowed| match auth_type.as_str() {
            "token" => {
                if let Some(token) = auth_data
                    .as_ref()
                    .and_then(|v| v.get("token"))
                    .and_then(|v| v.as_str())
                {
                    let user = username_from_url.unwrap_or("x-access-token");
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
    remote.fetch(&[&refspec], Some(&mut fetch_options), None)?;
    let reference_name = format!("refs/remotes/origin/{branch}");
    match repo.find_reference(&reference_name) {
        Ok(reference) => Ok(reference.target()),
        Err(err) if err.code() == git2::ErrorCode::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn fetch_remote_and_verify(
    repo: &Repository,
    cfg: &UserGitCfg,
    branch: &str,
    latest_meta: Option<&CommitMeta>,
) -> anyhow::Result<()> {
    if cfg.repository_url.is_empty() {
        return Ok(());
    }
    let remote_head = fetch_remote_head(repo, cfg, branch)?;
    match (latest_meta, remote_head) {
        (Some(meta), Some(oid)) => {
            if oid.as_bytes() != meta.commit_id.as_slice() {
                anyhow::bail!(
                    "remote repository state diverged: remote head {} does not match latest recorded commit {}",
                    oid.to_string(),
                    encode_commit_id(&meta.commit_id)
                );
            }
        }
        (None, Some(oid)) => {
            anyhow::bail!(
                "remote repository already contains commit {} but local repository has no history",
                oid.to_string()
            );
        }
        _ => {}
    }
    Ok(())
}

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
) -> anyhow::Result<bool> {
    let ref_name = format!("refs/heads/{}", branch);
    repo.reference(&ref_name, commit_oid, true, "update branch for sync")?;

    let mut remote = prepare_remote(repo, cfg)?;
    let callbacks = build_remote_callbacks(cfg);
    let mut push_options = PushOptions::new();
    push_options.remote_callbacks(callbacks);
    let refspec = format!("refs/heads/{}:refs/heads/{}", branch, cfg.branch_name);
    remote.push(&[&refspec], Some(&mut push_options))?;
    Ok(true)
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

#[derive(Default)]
struct DirNode {
    entries: BTreeMap<String, DirEntry>,
}

enum DirEntry {
    File(Vec<u8>),
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

fn repo_relative_path(path: &str) -> anyhow::Result<String> {
    let trimmed = path.trim_start_matches('/');
    let mut parts = trimmed.splitn(2, '/');
    let leading = parts.next().unwrap_or("");
    if let Some(rest) = parts.next() {
        Ok(rest.to_string())
    } else if !leading.is_empty() {
        Ok(leading.to_string())
    } else {
        Err(anyhow!("invalid storage path for repository: {path}"))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn blob_key(user_id: Uuid, commit_id: &[u8], path: &str) -> BlobKey {
    let encoded_path = urlencoding::encode(path);
    let commit_hex = encode_commit_id(commit_id);
    BlobKey {
        path: format!("{}/{}/{}", user_id, commit_hex, encoded_path),
    }
}
