use std::sync::Arc;

use uuid::Uuid;

use crate::core::ports::storage::storage_port::StorageResolverPort;
use crate::core::services::errors::ServiceError;
use crate::documents::dtos::{DocumentDownload, DocumentDownloadFormat, DocumentListFilter};
use crate::documents::ports::access_repository::AccessRepository;
use crate::documents::ports::doc_event_log::DocEventLog;
use crate::documents::ports::document_exporter::DocumentExporter;
use crate::documents::ports::document_repository::{DocMeta, DocumentRepository};
use crate::documents::ports::files::files_repository::FilesRepository;
use crate::documents::ports::linkgraph_repository::LinkGraphRepository;
use crate::documents::ports::realtime::realtime_port::RealtimeEngine;
use crate::documents::ports::sharing::share_access_port::ShareAccessPort;
use crate::documents::ports::tx_runner::DocumentsTxRunner;
use crate::documents::services::realtime::snapshot::SnapshotService;
use async_trait::async_trait;
use domain::access::permissions::PermissionSet;
use domain::documents::doc_type::DocumentType;
use domain::documents::document::Document as DomainDocument;
use domain::documents::document::{
    BacklinkInfo as DomainBacklink, OutgoingLink as DomainOutgoingLink, SearchHit,
};

mod attachments;
mod content;
mod crud;
mod deletion;
mod downloads;
mod events;
pub mod files;
mod jobs;
mod lifecycle;
pub mod linkgraph;
mod links;
mod patch;
pub mod publishing;
pub mod realtime;
pub mod sharing;
mod snapshot_dto;
mod snapshots;
pub mod tagging;
mod util;

pub use patch::DocumentPatchOperation;

#[async_trait]
pub trait DocumentServiceFacade: Send + Sync {
    async fn list_for_user(
        &self,
        workspace_id: Uuid,
        query: Option<String>,
        tag: Option<String>,
        state: DocumentListFilter,
    ) -> Result<Vec<DomainDocument>, ServiceError>;

    async fn search_for_user(
        &self,
        workspace_id: Uuid,
        query: Option<String>,
        limit: i64,
    ) -> Result<Vec<SearchHit>, ServiceError>;

    #[allow(clippy::too_many_arguments)]
    async fn create_for_user(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: DocumentType,
        created_by_plugin: Option<&str>,
    ) -> Result<DomainDocument, ServiceError>;

    async fn duplicate_document(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> Result<DomainDocument, ServiceError>;

    async fn get_for_actor(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
    ) -> Result<DomainDocument, ServiceError>;

    async fn delete_for_user(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Option<Uuid>,
        permissions: &PermissionSet,
    ) -> Result<bool, ServiceError>;

    async fn update_metadata(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> Result<DomainDocument, ServiceError>;

    async fn archive_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<DomainDocument, ServiceError>;

    async fn unarchive_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<DomainDocument, ServiceError>;

    async fn get_content(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
    ) -> Result<String, ServiceError>;

    async fn update_content(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        content: &str,
    ) -> Result<DomainDocument, ServiceError>;

    async fn patch_content(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        operations: &[DocumentPatchOperation],
    ) -> Result<DomainDocument, ServiceError>;

    async fn download_document(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        format: DocumentDownloadFormat,
    ) -> Result<DocumentDownload, ServiceError>;

    async fn download_workspace_root(
        &self,
        actor: &crate::core::services::access::Actor,
        workspace_id: Uuid,
        workspace_name: &str,
        format: DocumentDownloadFormat,
    ) -> Result<DocumentDownload, ServiceError>;

    async fn list_snapshots(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<crate::documents::dtos::SnapshotSummaryDto>, ServiceError>;

    async fn snapshot_diff(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
        compare: Option<Uuid>,
        base_mode: crate::documents::dtos::SnapshotDiffBaseMode,
    ) -> Result<crate::documents::dtos::SnapshotDiffDto, ServiceError>;

    async fn restore_snapshot(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
    ) -> Result<crate::documents::dtos::SnapshotSummaryDto, ServiceError>;

    async fn download_snapshot(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
    ) -> Result<crate::documents::use_cases::snapshot_download::SnapshotDownload, ServiceError>;

    async fn backlinks(
        &self,
        actor: &crate::core::services::access::Actor,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<DomainBacklink>, ServiceError>;

    async fn outgoing_links(
        &self,
        actor: &crate::core::services::access::Actor,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<DomainOutgoingLink>, ServiceError>;
}

#[async_trait]
impl DocumentServiceFacade for DocumentService {
    async fn list_for_user(
        &self,
        workspace_id: Uuid,
        query: Option<String>,
        tag: Option<String>,
        state: DocumentListFilter,
    ) -> Result<Vec<DomainDocument>, ServiceError> {
        self.list_for_user(workspace_id, query, tag, state).await
    }

    async fn search_for_user(
        &self,
        workspace_id: Uuid,
        query: Option<String>,
        limit: i64,
    ) -> Result<Vec<SearchHit>, ServiceError> {
        self.search_for_user(workspace_id, query, limit).await
    }

    async fn create_for_user(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: DocumentType,
        created_by_plugin: Option<&str>,
    ) -> Result<DomainDocument, ServiceError> {
        self.create_for_user(
            workspace_id,
            actor_id,
            permissions,
            title,
            parent_id,
            doc_type,
            created_by_plugin,
        )
        .await
    }

    async fn duplicate_document(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> Result<DomainDocument, ServiceError> {
        self.duplicate_document(
            workspace_id,
            source_id,
            actor_id,
            permissions,
            title,
            parent_id,
        )
        .await
    }

    async fn get_for_actor(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
    ) -> Result<DomainDocument, ServiceError> {
        self.get_for_actor(actor, doc_id).await
    }

    async fn delete_for_user(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Option<Uuid>,
        permissions: &PermissionSet,
    ) -> Result<bool, ServiceError> {
        self.delete_for_user(workspace_id, doc_id, actor_id, permissions)
            .await
    }

    async fn update_metadata(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> Result<DomainDocument, ServiceError> {
        self.update_metadata(
            workspace_id,
            doc_id,
            actor_id,
            permissions,
            title,
            parent_id,
        )
        .await
    }

    async fn archive_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<DomainDocument, ServiceError> {
        self.archive_document(workspace_id, doc_id, actor_id, permissions)
            .await
    }

    async fn unarchive_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<DomainDocument, ServiceError> {
        self.unarchive_document(workspace_id, doc_id, actor_id, permissions)
            .await
    }

    async fn get_content(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
    ) -> Result<String, ServiceError> {
        self.get_content(actor, doc_id).await
    }

    async fn update_content(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        content: &str,
    ) -> Result<DomainDocument, ServiceError> {
        self.update_content(actor, doc_id, content).await
    }

    async fn patch_content(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        operations: &[DocumentPatchOperation],
    ) -> Result<DomainDocument, ServiceError> {
        self.patch_content(actor, doc_id, operations).await
    }

    async fn download_document(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        format: DocumentDownloadFormat,
    ) -> Result<DocumentDownload, ServiceError> {
        self.download_document(actor, doc_id, format).await
    }

    async fn download_workspace_root(
        &self,
        actor: &crate::core::services::access::Actor,
        workspace_id: Uuid,
        workspace_name: &str,
        format: DocumentDownloadFormat,
    ) -> Result<DocumentDownload, ServiceError> {
        self.download_workspace_root(actor, workspace_id, workspace_name, format)
            .await
    }

    async fn list_snapshots(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<crate::documents::dtos::SnapshotSummaryDto>, ServiceError> {
        self.list_snapshots(actor, doc_id, limit, offset).await
    }

    async fn snapshot_diff(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
        compare: Option<Uuid>,
        base_mode: crate::documents::dtos::SnapshotDiffBaseMode,
    ) -> Result<crate::documents::dtos::SnapshotDiffDto, ServiceError> {
        self.snapshot_diff(actor, doc_id, snapshot_id, compare, base_mode)
            .await
    }

    async fn restore_snapshot(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
    ) -> Result<crate::documents::dtos::SnapshotSummaryDto, ServiceError> {
        self.restore_snapshot(actor, doc_id, snapshot_id).await
    }

    async fn download_snapshot(
        &self,
        actor: &crate::core::services::access::Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
    ) -> Result<crate::documents::use_cases::snapshot_download::SnapshotDownload, ServiceError>
    {
        self.download_snapshot(actor, doc_id, snapshot_id).await
    }

    async fn backlinks(
        &self,
        actor: &crate::core::services::access::Actor,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<DomainBacklink>, ServiceError> {
        self.backlinks(actor, workspace_id, doc_id).await
    }

    async fn outgoing_links(
        &self,
        actor: &crate::core::services::access::Actor,
        workspace_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<DomainOutgoingLink>, ServiceError> {
        self.outgoing_links(actor, workspace_id, doc_id).await
    }
}

pub struct DocumentService {
    tx_runner: Arc<dyn DocumentsTxRunner>,
    document_repo: Arc<dyn DocumentRepository>,
    files_repo: Arc<dyn FilesRepository>,
    access_repo: Arc<dyn AccessRepository>,
    share_access: Arc<dyn ShareAccessPort>,
    linkgraph_repo: Arc<dyn LinkGraphRepository>,
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
        linkgraph_repo: Arc<dyn LinkGraphRepository>,
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
            linkgraph_repo,
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
