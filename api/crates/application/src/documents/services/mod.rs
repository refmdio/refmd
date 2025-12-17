use std::sync::Arc;

use uuid::Uuid;

use crate::core::ports::storage::storage_port::StorageResolverPort;
use crate::documents::ports::access_repository::AccessRepository;
use crate::documents::ports::doc_event_log::DocEventLog;
use crate::documents::ports::document_exporter::DocumentExporter;
use crate::documents::ports::document_repository::{DocMeta, DocumentRepository};
use crate::documents::ports::files::files_repository::FilesRepository;
use crate::documents::ports::realtime::realtime_port::RealtimeEngine;
use crate::documents::ports::sharing::share_access_port::ShareAccessPort;
use crate::documents::ports::tx_runner::DocumentsTxRunner;
use crate::core::services::errors::ServiceError;
use crate::documents::services::realtime::snapshot::SnapshotService;

mod attachments;
mod deletion;
mod events;
mod jobs;
mod patch;
mod snapshot_dto;
mod util;
mod content;
mod crud;
mod downloads;
mod lifecycle;
mod links;
mod snapshots;
pub mod files;
pub mod linkgraph;
pub mod publishing;
pub mod realtime;
pub mod sharing;
pub mod tagging;

pub use patch::DocumentPatchOperation;

pub struct DocumentService {
    tx_runner: Arc<dyn DocumentsTxRunner>,
    document_repo: Arc<dyn DocumentRepository>,
    files_repo: Arc<dyn FilesRepository>,
    access_repo: Arc<dyn AccessRepository>,
    share_access: Arc<dyn ShareAccessPort>,
    storage: Arc<dyn StorageResolverPort>,
    events: Arc<dyn DocEventLog>,
    realtime: Arc<dyn RealtimeEngine>,
    snapshot_service: Arc<SnapshotService>,
    exporter: Arc<dyn DocumentExporter>,
}

impl DocumentService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_runner: Arc<dyn DocumentsTxRunner>,
        document_repo: Arc<dyn DocumentRepository>,
        files_repo: Arc<dyn FilesRepository>,
        access_repo: Arc<dyn AccessRepository>,
        share_access: Arc<dyn ShareAccessPort>,
        storage: Arc<dyn StorageResolverPort>,
        events: Arc<dyn DocEventLog>,
        realtime: Arc<dyn RealtimeEngine>,
        snapshot_service: Arc<SnapshotService>,
        exporter: Arc<dyn DocumentExporter>,
    ) -> Self {
        Self {
            tx_runner,
            document_repo,
            files_repo,
            access_repo,
            share_access,
            storage,
            events,
            realtime,
            snapshot_service,
            exporter,
        }
    }

    async fn load_owner_meta(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> Result<DocMeta, ServiceError> {
        self.document_repo
            .get_meta_for_owner(doc_id, workspace_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)
    }
}
