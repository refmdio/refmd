use std::sync::Arc;

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
use crate::application::ports::storage_port::StoragePort;
use crate::application::ports::storage_projection_queue::{
    StorageProjectionJobKind, StorageProjectionQueue,
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
    document_repo: Arc<dyn DocumentRepository>,
    files_repo: Arc<dyn FilesRepository>,
    access_repo: Arc<dyn AccessRepository>,
    share_access: Arc<dyn ShareAccessPort>,
    storage: Arc<dyn StoragePort>,
    events: Arc<dyn DocEventLog>,
    storage_jobs: Arc<dyn StorageProjectionQueue>,
    realtime: Arc<dyn RealtimeEngine>,
    snapshot_service: Arc<SnapshotService>,
    exporter: Arc<dyn DocumentExporter>,
}

impl DocumentService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        document_repo: Arc<dyn DocumentRepository>,
        files_repo: Arc<dyn FilesRepository>,
        access_repo: Arc<dyn AccessRepository>,
        share_access: Arc<dyn ShareAccessPort>,
        storage: Arc<dyn StoragePort>,
        events: Arc<dyn DocEventLog>,
        storage_jobs: Arc<dyn StorageProjectionQueue>,
        realtime: Arc<dyn RealtimeEngine>,
        snapshot_service: Arc<SnapshotService>,
        exporter: Arc<dyn DocumentExporter>,
    ) -> Self {
        Self {
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
        let doc = uc
            .execute(user_id, title, parent_id, doc_type)
            .await
            .map_err(ServiceError::from)?;
        self.enqueue_projection_for_document(&doc, "create_document")
            .await;
        let repo_path = self.repo_path_for_doc(doc.id).await;
        self.record_event(
            doc.id,
            "document.created",
            Some(json!({
                "title": doc.title,
                "parent_id": doc.parent_id,
                "doc_type": doc.doc_type,
                "repo_path": repo_path,
                "owner_id": user_id,
            })),
        )
        .await;
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
        let repo_path = meta.path.as_deref().and_then(repo_path_from_relative);
        let uc = DeleteDocument {
            repo: self.document_repo.as_ref(),
        };
        let result = uc
            .execute(doc_id, user_id)
            .await
            .map_err(ServiceError::from)?;
        if let Some(dtype) = result {
            match dtype.as_str() {
                "folder" => {
                    self.enqueue_folder_delete(doc_id, "delete_folder").await;
                }
                _ => {
                    self.enqueue_doc_delete(doc_id, "delete_document").await;
                }
            }
            self.record_event(
                doc_id,
                "document.deleted",
                Some(json!({
                    "doc_type": dtype,
                    "repo_path": repo_path,
                    "owner_id": user_id,
                })),
            )
            .await;
            Ok(true)
        } else {
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
        self.enqueue_doc_sync(doc.id, "update_content").await;
        let repo_path = self.repo_path_for_doc(doc.id).await;
        self.record_event(
            doc.id,
            "document.content_updated",
            Some(json!({
                "repo_path": repo_path,
                "doc_type": doc.doc_type,
            })),
        )
        .await;
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
            realtime: self.realtime.as_ref(),
            access: self.access_repo.as_ref(),
            shares: self.share_access.as_ref(),
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
        let doc = uc
            .execute(doc_id, user_id, title, parent_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        self.enqueue_projection_for_document(&doc, "update_metadata")
            .await;
        let repo_path = self.repo_path_for_doc(doc.id).await;
        self.record_event(
            doc.id,
            "document.metadata_updated",
            Some(json!({
                "title": doc.title,
                "parent_id": doc.parent_id,
                "repo_path": repo_path,
                "doc_type": doc.doc_type,
                "owner_id": user_id,
            })),
        )
        .await;
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
        let doc = uc
            .execute(user_id, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        self.enqueue_projection_for_document(&doc, "archive_document")
            .await;
        let repo_path = self.repo_path_for_doc(doc.id).await;
        self.record_event(
            doc.id,
            "document.archived",
            Some(json!({
                "repo_path": repo_path,
                "doc_type": doc.doc_type,
                "owner_id": user_id,
            })),
        )
        .await;
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
        let doc = uc
            .execute(user_id, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        self.enqueue_projection_for_document(&doc, "unarchive_document")
            .await;
        let repo_path = self.repo_path_for_doc(doc.id).await;
        self.record_event(
            doc.id,
            "document.unarchived",
            Some(json!({
                "repo_path": repo_path,
                "doc_type": doc.doc_type,
                "owner_id": user_id,
            })),
        )
        .await;
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

    async fn enqueue_projection_for_document(&self, doc: &DomainDocument, reason: &'static str) {
        if doc.doc_type == "folder" {
            self.enqueue_folder_sync(doc.id, reason).await;
        } else {
            self.enqueue_doc_sync(doc.id, reason).await;
        }
    }

    async fn enqueue_doc_sync(&self, doc_id: Uuid, reason: &'static str) {
        if let Err(err) = self
            .storage_jobs
            .enqueue_doc_job(doc_id, StorageProjectionJobKind::DocSync, Some(reason))
            .await
        {
            warn!(
                error = ?err,
                doc_id = %doc_id,
                "storage_projection_enqueue_failed"
            );
        }
    }

    async fn enqueue_doc_delete(&self, doc_id: Uuid, reason: &'static str) {
        if let Err(err) = self
            .storage_jobs
            .enqueue_doc_job(doc_id, StorageProjectionJobKind::DeleteDoc, Some(reason))
            .await
        {
            warn!(
                error = ?err,
                doc_id = %doc_id,
                "storage_projection_enqueue_failed"
            );
        }
    }

    async fn enqueue_folder_sync(&self, folder_id: Uuid, reason: &'static str) {
        if let Err(err) = self
            .storage_jobs
            .enqueue_folder_job(
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

    async fn enqueue_folder_delete(&self, folder_id: Uuid, reason: &'static str) {
        if let Err(err) = self
            .storage_jobs
            .enqueue_folder_job(
                folder_id,
                StorageProjectionJobKind::DeleteFolder,
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

    async fn record_event(
        &self,
        doc_id: Uuid,
        event_type: &'static str,
        payload: Option<serde_json::Value>,
    ) {
        if let Err(err) = self.events.append(doc_id, event_type, payload).await {
            warn!(
                error = ?err,
                doc_id = %doc_id,
                event_type,
                "doc_event_log_append_failed"
            );
        }
    }

    async fn repo_path_for_doc(&self, doc_id: Uuid) -> Option<String> {
        if let Ok(Some(doc)) = self.document_repo.get_by_id(doc_id).await {
            if let Some(path) = doc.path {
                return repo_path_from_relative(&path);
            }
        }
        match self.storage.build_doc_file_path(doc_id).await {
            Ok(path) => {
                let relative = self.storage.relative_from_uploads(path.as_path());
                repo_path_from_relative(&relative)
            }
            Err(_) => None,
        }
    }
}

fn repo_path_from_relative(relative: &str) -> Option<String> {
    let normalized = relative.replace('\\', "/");
    let trimmed = normalized.trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .split_once('/')
        .map(|(_, rest)| rest.to_string())
        .or_else(|| Some(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::repo_path_from_relative;

    #[test]
    fn repo_path_drops_owner_prefix() {
        let owner = uuid::Uuid::new_v4();
        let rel = format!("{}/notes/foo.md", owner);
        assert_eq!(
            repo_path_from_relative(&rel),
            Some("notes/foo.md".to_string())
        );
    }

    #[test]
    fn repo_path_handles_missing_repo_segment() {
        let rel = "";
        assert_eq!(repo_path_from_relative(rel), None);

        let rel2 = "leading-no-owner";
        assert_eq!(
            repo_path_from_relative(rel2),
            Some("leading-no-owner".to_string())
        );
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
