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
    CertificateCheckStatus, Commit, Cred, Error as GitError, ErrorClass, FetchOptions, FileMode,
    Indexer, ObjectType, PushOptions, RemoteCallbacks, Repository, Signature, Sort, Time,
    TreeWalkMode, TreeWalkResult,
};
use sqlx::{Row, types::Json};
use tempfile::{Builder as TempDirBuilder, TempDir};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::core::db::PgPool;
use application::core::dtos::TextDiffResult;
use application::core::ports::errors::PortResult;
use application::core::ports::storage::storage_port::StorageResolverPort;
use application::core::services::diff::text_diff::compute_text_diff;
use application::core::services::utils::hash::sha256_hex;
use application::documents::ports::document_path_repository::DocumentPathRepository;
use application::documents::ports::document_repository::DocumentRepository;
use application::documents::ports::realtime::realtime_port::RealtimeEngine;
use application::documents::services::realtime::snapshot::{
    SnapshotService, snapshot_from_markdown,
};
use application::git::dtos::{
    GitChangeItem, GitCommitInfo, GitImportOutcome, GitPullConflictItemDto, GitPullRequestDto,
    GitPullResultDto, GitRemoteCheckDto, GitSyncOutcome, GitSyncRequestDto, GitWorkspaceStatus,
};
use application::git::ports::git_repository::UserGitCfg;
use application::git::ports::git_storage::{
    BlobKey, CommitMeta, GitStorage, decode_commit_id, encode_commit_id,
};
use application::git::ports::git_workspace::GitWorkspacePort;
use tokio::fs as async_fs;

mod helpers;
use helpers::*;

pub struct GitWorkspaceService {
    pool: PgPool,
    git_storage: Arc<dyn GitStorage>,
    storage: Arc<dyn StorageResolverPort>,
    snapshot: Arc<SnapshotService>,
    realtime: Arc<dyn RealtimeEngine>,
    docs: Arc<dyn DocumentRepository>,
    doc_paths: Arc<dyn DocumentPathRepository>,
}

include!("workspace_service.rs");
include!("sync.rs");
include!("import.rs");
include!("remote.rs");
include!("port.rs");
include!("pull.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_build_commit_pack_skips_noop_commit_on_full_scan() -> anyhow::Result<()> {
        let temp_dir = TempDirBuilder::new().prefix("git-sync-test-").tempdir()?;
        let repo = Repository::init_bare(temp_dir.path())?;

        let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        entries.insert("doc.md".to_string(), b"hello".to_vec());

        let base_tree_oid = build_tree_from_entries(&repo, &entries)?;
        let base_tree = repo.find_tree(base_tree_oid)?;
        let sig = signature_from_parts("RefMD", "refmd@example.com", Utc::now())?;
        let base_oid = repo.commit(Some("refs/heads/main"), &sig, &sig, "base", &base_tree, &[])?;

        let latest_meta = CommitMeta {
            commit_id: base_oid.as_bytes().to_vec(),
            parent_commit_id: None,
            message: None,
            author_name: None,
            author_email: None,
            committed_at: Utc::now(),
            pack_key: String::new(),
            file_hash_index: HashMap::new(),
        };

        let outcome = GitWorkspaceService::sync_build_commit_pack(
            Uuid::new_v4(),
            &repo,
            Some(&latest_meta),
            "main",
            "RefMD",
            "refmd@example.com",
            Utc::now(),
            "Automated Git rebuild",
            true,
            Some(&entries),
            &BTreeSet::new(),
            &BTreeMap::new(),
            HashMap::new(),
            None,
            true,
            false,
        )?;

        match outcome {
            SyncBuildCommitPackOutcome::NoChanges { commit_hex, pushed } => {
                assert_eq!(commit_hex, encode_commit_id(base_oid.as_bytes()));
                assert!(!pushed);
            }
            SyncBuildCommitPackOutcome::Committed { .. } => {
                anyhow::bail!("expected NoChanges, got Committed")
            }
        }

        Ok(())
    }
}
