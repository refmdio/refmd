use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::documents::ports::doc_event_log::DocEventLog;
use crate::documents::ports::document_repository::DocumentRepository;
use crate::documents::ports::files::files_repository::FilesRepository;
use crate::documents::ports::realtime::realtime_port::RealtimeEngine;
use crate::core::ports::storage::storage_ingest_queue::{StorageIngestEvent, StorageIngestKind};
use crate::core::ports::storage::storage_port::{StorageProjectionPort, StorageResolverPort};
use crate::documents::services::DocumentService;
use crate::core::services::errors::ServiceError;
use crate::documents::services::realtime::snapshot::snapshot_from_markdown;
use crate::core::services::storage::projection_cache::RecentProjectionCache;
use crate::workspaces::services::{
    WorkspacePermissionResolver, permission_snapshot::permission_set_from_snapshot,
};
use crate::core::services::utils::hash::sha256_hex;
use domain::documents::document::Document as DomainDocument;
use domain::workspaces::permissions::PermissionSet;

mod attachments;
mod documents;
mod handler;
mod markdown;
mod permissions;
mod resolved_document;
mod utils;

pub use domain::documents::path::normalize_repo_path;

use markdown::{MarkdownIngestPayload, parse_markdown_payload};
use resolved_document::ResolvedDocument;
use utils::{is_not_found_error, previous_path_from_payload};

#[async_trait]
pub trait StorageIngestHandler: Send + Sync {
    async fn handle_event(&self, event: &StorageIngestEvent) -> anyhow::Result<()>;
}

pub struct StorageIngestService {
    document_repo: Arc<dyn DocumentRepository>,
    files_repo: Arc<dyn FilesRepository>,
    realtime: Arc<dyn RealtimeEngine>,
    storage: Arc<dyn StorageResolverPort>,
    storage_projection: Arc<dyn StorageProjectionPort>,
    events: Arc<dyn DocEventLog>,
    document_service: Arc<DocumentService>,
    permission_resolver: Arc<dyn WorkspacePermissionResolver>,
    recent_exports: Arc<RecentProjectionCache>,
}

impl StorageIngestService {
    pub fn new(
        document_repo: Arc<dyn DocumentRepository>,
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
