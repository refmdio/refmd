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
