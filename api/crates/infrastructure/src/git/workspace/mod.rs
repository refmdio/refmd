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

use application::contracts::diff::TextDiffResult;
use application::contracts::git::{
    GitChangeItem, GitCommitInfo, GitImportOutcome, GitPullConflictItemDto, GitPullRequestDto,
    GitPullResultDto, GitRemoteCheckDto, GitSyncOutcome, GitSyncRequestDto, GitWorkspaceStatus,
};
use application::ports::document_repository::DocumentRepository;
use application::ports::git_repository::UserGitCfg;
use application::ports::git_storage::{
    BlobKey, CommitMeta, GitStorage, decode_commit_id, encode_commit_id,
};
use application::ports::git_workspace::GitWorkspacePort;
use application::ports::realtime_port::RealtimeEngine;
use application::ports::storage_port::StorageResolverPort;
use application::services::diff::text_diff::compute_text_diff;
use application::services::realtime::snapshot::{SnapshotService, snapshot_from_markdown};
use application::utils::hash::sha256_hex;
use crate::db::PgPool;
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
}

include!("service.rs");
include!("sync.rs");
include!("import.rs");
include!("remote.rs");
include!("port.rs");
include!("pull.rs");
