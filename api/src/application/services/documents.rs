use std::sync::Arc;

use sqlx::{Pool, Postgres, Transaction};
use tracing::warn;
use uuid::Uuid;

use crate::application::access::{self, Actor};
use crate::application::dto::document_export::{DocumentDownload, DocumentDownloadFormat};
use crate::application::dto::documents::{
    DocumentListFilter, SnapshotDiffBaseMode, SnapshotDiffDto, SnapshotDiffSideDto,
    SnapshotSummaryDto,
};
use crate::application::ports::access_repository::AccessRepository;
use crate::application::ports::doc_event_log::DocEventLog;
use crate::application::ports::document_exporter::DocumentExporter;
use crate::application::ports::document_repository::{
    DocMeta, DocumentListState, DocumentRepository,
};
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::realtime_port::RealtimeEngine;
use crate::application::ports::share_access_port::ShareAccessPort;
use crate::application::ports::storage_port::StorageResolverPort;
use crate::application::ports::storage_projection_queue::{
    StorageDeleteJobMetadata, StorageJobReason, StorageProjectionJobKind, StorageProjectionQueue,
};
use crate::application::services::errors::ServiceError;
use crate::application::services::realtime::snapshot::{SnapshotService, snapshot_from_markdown};
use crate::application::use_cases::documents::archive_document::ArchiveDocument;
use crate::application::use_cases::documents::create_document::CreateDocument;
use crate::application::use_cases::documents::delete_document::DeleteDocument;
use crate::application::use_cases::documents::download_document::DownloadDocument as DownloadDocumentUseCase;
use crate::application::use_cases::documents::get_backlinks::GetBacklinks;
use crate::application::use_cases::documents::get_document::GetDocument;
use crate::application::use_cases::documents::get_outgoing_links::GetOutgoingLinks;
use crate::application::use_cases::documents::list_documents::ListDocuments;
use crate::application::use_cases::documents::list_snapshots::ListSnapshots;
use crate::application::use_cases::documents::restore_snapshot::RestoreSnapshot;
use crate::application::use_cases::documents::search_documents::SearchDocuments;
use crate::application::use_cases::documents::snapshot_diff::{
    SnapshotDiff, SnapshotDiffResult, SnapshotDiffSide,
};
use crate::application::use_cases::documents::snapshot_download::{
    DownloadSnapshot, SnapshotDownload,
};
use crate::application::use_cases::documents::unarchive_document::UnarchiveDocument;
use crate::application::use_cases::documents::update_document::UpdateDocument;
use crate::domain::documents::document::{
    BacklinkInfo as DomainBacklink, Document as DomainDocument, OutgoingLink as DomainOutgoingLink,
    SearchHit,
};
use serde_json::json;

pub struct DocumentService {
    db: Pool<Postgres>,
    document_repo: Arc<dyn DocumentRepository>,
    files_repo: Arc<dyn FilesRepository>,
    access_repo: Arc<dyn AccessRepository>,
    share_access: Arc<dyn ShareAccessPort>,
    storage: Arc<dyn StorageResolverPort>,
    events: Arc<dyn DocEventLog>,
    storage_jobs: Arc<dyn StorageProjectionQueue>,
    realtime: Arc<dyn RealtimeEngine>,
    snapshot_service: Arc<SnapshotService>,
    exporter: Arc<dyn DocumentExporter>,
}

impl DocumentService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Pool<Postgres>,
        document_repo: Arc<dyn DocumentRepository>,
        files_repo: Arc<dyn FilesRepository>,
        access_repo: Arc<dyn AccessRepository>,
        share_access: Arc<dyn ShareAccessPort>,
        storage: Arc<dyn StorageResolverPort>,
        events: Arc<dyn DocEventLog>,
        storage_jobs: Arc<dyn StorageProjectionQueue>,
        realtime: Arc<dyn RealtimeEngine>,
        snapshot_service: Arc<SnapshotService>,
        exporter: Arc<dyn DocumentExporter>,
    ) -> Self {
        Self {
            db,
            document_repo,
            files_repo,
            access_repo,
            share_access,
            storage,
            events,
            storage_jobs,
            realtime,
            snapshot_service,
            exporter,
        }
    }

    async fn begin_transaction(&self) -> Result<Transaction<'_, Postgres>, ServiceError> {
        self.db.begin().await.map_err(map_sqlx_error)
    }

    pub async fn list_for_user(
        &self,
        user_id: Uuid,
        query: Option<String>,
        tag: Option<String>,
        state: DocumentListFilter,
    ) -> Result<Vec<DomainDocument>, ServiceError> {
        let uc = ListDocuments {
            repo: self.document_repo.as_ref(),
        };
        uc.execute(user_id, query, tag, to_repo_state(state))
            .await
            .map_err(ServiceError::from)
    }

    pub async fn create_for_user(
        &self,
        user_id: Uuid,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: &str,
    ) -> Result<DomainDocument, ServiceError> {
        if let Some(parent_id) = parent_id {
            self.ensure_active_parent(user_id, parent_id).await?;
        }
        let uc = CreateDocument {
            repo: self.document_repo.as_ref(),
        };
        let mut tx = self.begin_transaction().await?;
        let doc = uc
            .execute_tx(&mut tx, user_id, title, parent_id, doc_type)
            .await
            .map_err(ServiceError::from)?;
        self.enqueue_projection_for_document_tx(&mut tx, &doc, "create_document")
            .await;
        let repo_path = doc.desired_path.clone();
        self.record_event_tx(
            &mut tx,
            doc.id,
            "document.created",
            Some(json!({
                "title": doc.title,
                "parent_id": doc.parent_id,
                "doc_type": doc.doc_type,
                "repo_path": repo_path,
                "slug": doc.slug,
                "desired_path": doc.desired_path,
                "owner_id": doc.owner_id,
            })),
        )
        .await;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(doc)
    }

    pub async fn get_for_actor(
        &self,
        actor: &Actor,
        doc_id: Uuid,
    ) -> Result<DomainDocument, ServiceError> {
        let uc = GetDocument {
            repo: self.document_repo.as_ref(),
            shares: self.share_access.as_ref(),
            access: self.access_repo.as_ref(),
        };
        uc.execute(actor, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn delete_for_user(&self, doc_id: Uuid, user_id: Uuid) -> Result<bool, ServiceError> {
        let meta = self.load_owner_meta(doc_id, user_id).await?;
        let repo_path = meta.desired_path.clone();
        let uc = DeleteDocument {
            repo: self.document_repo.as_ref(),
        };
        let mut tx = self.begin_transaction().await?;
        let result = uc
            .execute_tx(&mut tx, doc_id, user_id)
            .await
            .map_err(ServiceError::from)?;
        if let Some(dtype) = result {
            match dtype.as_str() {
                "folder" => {
                    let metadata = StorageDeleteJobMetadata {
                        owner_id: user_id,
                        repo_path: Some(repo_path.clone()),
                        doc_type: dtype.clone(),
                    };
                    self.enqueue_folder_delete_tx(&mut tx, doc_id, "delete_folder", Some(metadata))
                        .await;
                }
                _ => {
                    let metadata = StorageDeleteJobMetadata {
                        owner_id: user_id,
                        repo_path: Some(repo_path.clone()),
                        doc_type: dtype.clone(),
                    };
                    self.enqueue_doc_delete_tx(&mut tx, doc_id, "delete_document", Some(metadata))
                        .await;
                }
            }
            self.record_event_tx(
                &mut tx,
                doc_id,
                "document.deleted",
                Some(json!({
                    "doc_type": dtype,
                    "repo_path": repo_path,
                    "slug": meta.slug,
                    "desired_path": meta.desired_path,
                    "owner_id": user_id,
                })),
            )
            .await;
            tx.commit().await.map_err(map_sqlx_error)?;
            Ok(true)
        } else {
            tx.rollback().await.map_err(map_sqlx_error)?;
            Ok(false)
        }
    }

    pub async fn get_content(&self, actor: &Actor, doc_id: Uuid) -> Result<String, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::NotFound)?;

        let content = self
            .realtime
            .get_content(&doc_id.to_string())
            .await
            .map_err(ServiceError::from)?
            .unwrap_or_default();
        Ok(content)
    }

    pub async fn update_content(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        content: &str,
    ) -> Result<DomainDocument, ServiceError> {
        access::require_edit(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::Unauthorized)?;

        let snapshot_bytes = snapshot_from_markdown(content);
        self.realtime
            .apply_snapshot(&doc_id.to_string(), snapshot_bytes.as_slice())
            .await
            .map_err(ServiceError::from)?;

        if let Err(err) = self.realtime.force_persist(&doc_id.to_string()).await {
            warn!(document_id = %doc_id, error = ?err, "document_force_persist_after_update_failed");
        }

        let doc = self
            .document_repo
            .get_by_id(doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        let mut tx = self.begin_transaction().await?;
        self.enqueue_doc_sync_tx(&mut tx, doc.id, "update_content")
            .await;
        let repo_path = doc.desired_path.clone();
        self.record_event_tx(
            &mut tx,
            doc.id,
            "document.content_updated",
            Some(json!({
                "repo_path": repo_path,
                "desired_path": doc.desired_path,
                "slug": doc.slug,
                "doc_type": doc.doc_type,
                "owner_id": doc.owner_id,
            })),
        )
        .await;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(doc)
    }

    pub async fn download_document(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        format: DocumentDownloadFormat,
    ) -> Result<DocumentDownload, ServiceError> {
        let uc = DownloadDocumentUseCase {
            documents: self.document_repo.as_ref(),
            files: self.files_repo.as_ref(),
            storage: self.storage.as_ref(),
            access: self.access_repo.as_ref(),
            shares: self.share_access.as_ref(),
            snapshot: self.snapshot_service.as_ref(),
            exporter: self.exporter.as_ref(),
        };
        uc.execute(actor, doc_id, format)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn update_metadata(
        &self,
        doc_id: Uuid,
        user_id: Uuid,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> Result<DomainDocument, ServiceError> {
        let meta = self.load_owner_meta(doc_id, user_id).await?;
        if meta.archived_at.is_some() {
            return Err(ServiceError::Conflict);
        }
        if let Some(Some(parent)) = parent_id {
            self.ensure_active_parent(user_id, parent).await?;
        }
        let uc = UpdateDocument {
            repo: self.document_repo.as_ref(),
        };
        let mut tx = self.begin_transaction().await?;
        let doc = uc
            .execute_tx(&mut tx, doc_id, user_id, title, parent_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        self.enqueue_projection_for_document_tx(&mut tx, &doc, "update_metadata")
            .await;
        let repo_path = doc.desired_path.clone();
        self.record_event_tx(
            &mut tx,
            doc.id,
            "document.metadata_updated",
            Some(json!({
                "title": doc.title,
                "parent_id": doc.parent_id,
                "repo_path": repo_path,
                "doc_type": doc.doc_type,
                "slug": doc.slug,
                "desired_path": doc.desired_path,
                "owner_id": doc.owner_id,
            })),
        )
        .await;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(doc)
    }

    pub async fn archive_document(
        &self,
        doc_id: Uuid,
        user_id: Uuid,
    ) -> Result<DomainDocument, ServiceError> {
        let meta = self.load_owner_meta(doc_id, user_id).await?;
        if meta.archived_at.is_some() {
            return Err(ServiceError::Conflict);
        }
        let uc = ArchiveDocument {
            repo: self.document_repo.as_ref(),
            realtime: self.realtime.as_ref(),
        };
        let mut tx = self.begin_transaction().await?;
        let doc = uc
            .execute_tx(&mut tx, user_id, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        self.enqueue_projection_for_document_tx(&mut tx, &doc, "archive_document")
            .await;
        let repo_path = doc.desired_path.clone();
        self.record_event_tx(
            &mut tx,
            doc.id,
            "document.archived",
            Some(json!({
                "repo_path": repo_path,
                "doc_type": doc.doc_type,
                "slug": doc.slug,
                "desired_path": doc.desired_path,
                "owner_id": doc.owner_id,
            })),
        )
        .await;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(doc)
    }

    pub async fn unarchive_document(
        &self,
        doc_id: Uuid,
        user_id: Uuid,
    ) -> Result<DomainDocument, ServiceError> {
        let meta = self.load_owner_meta(doc_id, user_id).await?;
        if meta.archived_at.is_none() {
            return Err(ServiceError::Conflict);
        }
        let uc = UnarchiveDocument {
            repo: self.document_repo.as_ref(),
            realtime: self.realtime.as_ref(),
        };
        let mut tx = self.begin_transaction().await?;
        let doc = uc
            .execute_tx(&mut tx, user_id, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        self.enqueue_projection_for_document_tx(&mut tx, &doc, "unarchive_document")
            .await;
        let repo_path = doc.desired_path.clone();
        self.record_event_tx(
            &mut tx,
            doc.id,
            "document.unarchived",
            Some(json!({
                "repo_path": repo_path,
                "doc_type": doc.doc_type,
                "slug": doc.slug,
                "desired_path": doc.desired_path,
                "owner_id": doc.owner_id,
            })),
        )
        .await;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(doc)
    }

    pub async fn list_snapshots(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SnapshotSummaryDto>, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::Unauthorized)?;

        let uc = ListSnapshots {
            snapshots: self.snapshot_service.as_ref(),
        };
        let records = uc
            .execute(doc_id, limit, offset)
            .await
            .map_err(ServiceError::from)?;
        Ok(records.into_iter().map(SnapshotSummaryDto::from).collect())
    }

    pub async fn snapshot_diff(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
        compare: Option<Uuid>,
        base_mode: SnapshotDiffBaseMode,
    ) -> Result<SnapshotDiffDto, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::Unauthorized)?;

        let uc = SnapshotDiff {
            snapshots: self.snapshot_service.as_ref(),
            realtime: self.realtime.as_ref(),
        };
        let result = uc
            .execute(doc_id, snapshot_id, compare, base_mode)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        Ok(snapshot_diff_dto_from_result(result))
    }

    pub async fn restore_snapshot(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
    ) -> Result<SnapshotSummaryDto, ServiceError> {
        access::require_edit(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::Unauthorized)?;

        let created_by = match actor {
            Actor::User(uid) => Some(*uid),
            _ => None,
        };

        let uc = RestoreSnapshot {
            snapshots: self.snapshot_service.as_ref(),
            realtime: self.realtime.as_ref(),
        };
        let record = uc
            .execute(doc_id, snapshot_id, created_by)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;

        Ok(SnapshotSummaryDto::from(record))
    }

    pub async fn download_snapshot(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        snapshot_id: Uuid,
    ) -> Result<SnapshotDownload, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::Unauthorized)?;

        let uc = DownloadSnapshot {
            files: self.files_repo.as_ref(),
            storage: self.storage.as_ref(),
            snapshots: self.snapshot_service.as_ref(),
        };
        uc.execute(doc_id, snapshot_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn search_for_user(
        &self,
        user_id: Uuid,
        query: Option<String>,
        limit: i64,
    ) -> Result<Vec<SearchHit>, ServiceError> {
        let uc = SearchDocuments {
            repo: self.document_repo.as_ref(),
        };
        uc.execute(user_id, query, limit)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn backlinks(
        &self,
        actor: &Actor,
        owner_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<DomainBacklink>, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::NotFound)?;

        let uc = GetBacklinks {
            repo: self.document_repo.as_ref(),
        };
        uc.execute(owner_id, doc_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn outgoing_links(
        &self,
        actor: &Actor,
        owner_id: Uuid,
        doc_id: Uuid,
    ) -> Result<Vec<DomainOutgoingLink>, ServiceError> {
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::NotFound)?;

        let uc = GetOutgoingLinks {
            repo: self.document_repo.as_ref(),
        };
        uc.execute(owner_id, doc_id)
            .await
            .map_err(ServiceError::from)
    }

    async fn ensure_active_parent(
        &self,
        owner_id: Uuid,
        parent_id: Uuid,
    ) -> Result<(), ServiceError> {
        match self
            .document_repo
            .get_meta_for_owner(parent_id, owner_id)
            .await
            .map_err(ServiceError::from)?
        {
            Some(meta) => {
                if meta.archived_at.is_some() {
                    Err(ServiceError::Conflict)
                } else {
                    Ok(())
                }
            }
            None => Err(ServiceError::NotFound),
        }
    }

    async fn load_owner_meta(&self, doc_id: Uuid, owner_id: Uuid) -> Result<DocMeta, ServiceError> {
        self.document_repo
            .get_meta_for_owner(doc_id, owner_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)
    }

    async fn enqueue_projection_for_document_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc: &DomainDocument,
        reason: &'static str,
    ) {
        if doc.doc_type == "folder" {
            self.enqueue_folder_sync_tx(tx, doc.id, reason).await;
        } else {
            self.enqueue_doc_sync_tx(tx, doc.id, reason).await;
        }
    }

    async fn enqueue_doc_sync_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        reason: &'static str,
    ) {
        if let Err(err) = self
            .storage_jobs
            .enqueue_doc_job_tx(tx, doc_id, StorageProjectionJobKind::DocSync, Some(reason))
            .await
        {
            warn!(
                error = ?err,
                doc_id = %doc_id,
                "storage_projection_enqueue_failed"
            );
        }
    }

    async fn enqueue_doc_delete_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        reason: &'static str,
        metadata: Option<StorageDeleteJobMetadata>,
    ) {
        let encoded_reason = metadata.and_then(|meta| {
            serde_json::to_string(&StorageJobReason {
                reason: reason.to_string(),
                metadata: Some(meta),
            })
            .ok()
        });
        let reason_str = encoded_reason.as_deref().unwrap_or(reason);
        if let Err(err) = self
            .storage_jobs
            .enqueue_doc_job_tx(
                tx,
                doc_id,
                StorageProjectionJobKind::DeleteDoc,
                Some(reason_str),
            )
            .await
        {
            warn!(
                error = ?err,
                doc_id = %doc_id,
                "storage_projection_enqueue_failed"
            );
        }
    }

    async fn enqueue_folder_sync_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        folder_id: Uuid,
        reason: &'static str,
    ) {
        if let Err(err) = self
            .storage_jobs
            .enqueue_folder_job_tx(
                tx,
                folder_id,
                StorageProjectionJobKind::FolderSync,
                Some(reason),
            )
            .await
        {
            warn!(
                error = ?err,
                folder_id = %folder_id,
                "storage_projection_enqueue_failed"
            );
        }
    }

    async fn enqueue_folder_delete_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        folder_id: Uuid,
        reason: &'static str,
        metadata: Option<StorageDeleteJobMetadata>,
    ) {
        let encoded_reason = metadata.and_then(|meta| {
            serde_json::to_string(&StorageJobReason {
                reason: reason.to_string(),
                metadata: Some(meta),
            })
            .ok()
        });
        let reason_str = encoded_reason.as_deref().unwrap_or(reason);
        if let Err(err) = self
            .storage_jobs
            .enqueue_folder_job_tx(
                tx,
                folder_id,
                StorageProjectionJobKind::DeleteFolder,
                Some(reason_str),
            )
            .await
        {
            warn!(
                error = ?err,
                folder_id = %folder_id,
                "storage_projection_enqueue_failed"
            );
        }
    }

    async fn record_event_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        event_type: &'static str,
        payload: Option<serde_json::Value>,
    ) {
        if let Err(err) = self.events.append_tx(tx, doc_id, event_type, payload).await {
            warn!(
                error = ?err,
                doc_id = %doc_id,
                event_type,
                "doc_event_log_append_failed"
            );
        }
    }
}

fn snapshot_diff_dto_from_result(result: SnapshotDiffResult) -> SnapshotDiffDto {
    SnapshotDiffDto {
        base: snapshot_diff_side_from_use_case(result.base),
        target: snapshot_diff_side_from_use_case(result.target),
        diff: result.diff,
    }
}

fn snapshot_diff_side_from_use_case(side: SnapshotDiffSide) -> SnapshotDiffSideDto {
    match side {
        SnapshotDiffSide::Current { markdown } => SnapshotDiffSideDto::Current { markdown },
        SnapshotDiffSide::Snapshot { record, markdown } => SnapshotDiffSideDto::Snapshot {
            snapshot: SnapshotSummaryDto::from(record),
            markdown,
        },
    }
}

fn to_repo_state(filter: DocumentListFilter) -> DocumentListState {
    match filter {
        DocumentListFilter::Active => DocumentListState::Active,
        DocumentListFilter::Archived => DocumentListState::Archived,
        DocumentListFilter::All => DocumentListState::All,
    }
}

fn map_sqlx_error(err: sqlx::Error) -> ServiceError {
    ServiceError::Unexpected(err.into())
}
