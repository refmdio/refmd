use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::core::ports::storage::storage_ingest_queue::{StorageIngestEvent, StorageIngestKind};
use crate::core::ports::storage::storage_port::{StorageProjectionPort, StorageResolverPort};
use crate::core::services::errors::ServiceError;
use crate::core::services::storage::projection_cache::RecentProjectionCache;
use crate::core::services::utils::hash::sha256_hex;
use crate::documents::ports::doc_event_log::DocEventLog;
use crate::documents::ports::document_path_repository::DocumentPathRepository;
use crate::documents::ports::document_repository::DocumentRepository;
use crate::documents::ports::files::files_repository::FilesRepository;
use crate::documents::ports::realtime::realtime_port::RealtimeEngine;
use crate::documents::services::DocumentService;
use crate::workspaces::services::{
    WorkspacePermissionResolver, permission_snapshot::permission_set_from_snapshot,
};
use domain::access::permissions::PermissionSet;
use domain::documents::document::Document as DomainDocument;

mod attachments;
mod documents;
mod handler;
mod markdown;
mod permissions;
mod resolved_document;
mod utils;

/// RME1 (RefMD Encrypted v1) magic number for E2EE file format
pub const RME1_MAGIC: &[u8; 4] = b"RME1";

pub use domain::documents::path::normalize_repo_path;

use markdown::{MarkdownIngestPayload, parse_markdown_payload};
use resolved_document::ResolvedDocument;
use utils::{is_not_found_error, previous_path_from_payload};

#[async_trait]
pub trait StorageIngestHandler: Send + Sync {
    async fn handle_event(&self, event: &StorageIngestEvent) -> anyhow::Result<()>;
}

pub struct StorageIngestService {
    // TODO(e2ee): Remove after E2EE migration complete - was used for resolve_doc_from_front_matter
    #[allow(dead_code)]
    document_repo: Arc<dyn DocumentRepository>,
    document_paths: Arc<dyn DocumentPathRepository>,
    files_repo: Arc<dyn FilesRepository>,
    // TODO(e2ee): Remove after E2EE migration complete - was used for Yjs snapshot conversion
    #[allow(dead_code)]
    realtime: Arc<dyn RealtimeEngine>,
    storage: Arc<dyn StorageResolverPort>,
    storage_projection: Arc<dyn StorageProjectionPort>,
    events: Arc<dyn DocEventLog>,
    document_service: Arc<DocumentService>,
    permission_resolver: Arc<dyn WorkspacePermissionResolver>,
    recent_exports: Arc<RecentProjectionCache>,
}

impl StorageIngestService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        document_repo: Arc<dyn DocumentRepository>,
        document_paths: Arc<dyn DocumentPathRepository>,
        files_repo: Arc<dyn FilesRepository>,
        realtime: Arc<dyn RealtimeEngine>,
        storage: Arc<dyn StorageResolverPort>,
        storage_projection: Arc<dyn StorageProjectionPort>,
        events: Arc<dyn DocEventLog>,
        document_service: Arc<DocumentService>,
        permission_resolver: Arc<dyn WorkspacePermissionResolver>,
        recent_exports: Arc<RecentProjectionCache>,
    ) -> Self {
        Self {
            document_repo,
            document_paths,
            files_repo,
            realtime,
            storage,
            storage_projection,
            events,
            document_service,
            permission_resolver,
            recent_exports,
        }
    }

    fn relative_path(user_id: Uuid, repo_path: &str) -> String {
        let mut path = PathBuf::from(user_id.to_string());
        path.push(repo_path);
        path.to_string_lossy().replace('\\', "/")
    }
}
