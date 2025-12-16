use std::path::Path;
use std::sync::Arc;

use sqlx::{Pool, Postgres, Transaction};
use tracing::{error, warn};
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
    DocMeta, DocumentListState, DocumentPathConflictError, DocumentRepository,
};
use crate::application::ports::files_repository::FilesRepository;
use crate::application::ports::realtime_port::RealtimeEngine;
use crate::application::ports::share_access_port::ShareAccessPort;
use crate::application::ports::storage_port::StorageResolverPort;
use crate::application::ports::storage_projection_queue::{
    StorageDeleteJobMetadata, StorageJobReason, StorageProjectionJobKind, StorageProjectionQueue,
    WorkspaceJobMetadata,
};
use crate::application::services::errors::ServiceError;
use crate::application::services::realtime::snapshot::{SnapshotService, snapshot_from_markdown};
use crate::application::use_cases::documents::archive_document::ArchiveDocument;
use crate::application::use_cases::documents::create_document::CreateDocument;
use crate::application::use_cases::documents::delete_document::DeleteDocument;
use crate::application::use_cases::documents::download_document::{
    DownloadDocument as DownloadDocumentUseCase, FolderDownloadUnsupportedFormat,
};
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
use crate::application::utils::hash::sha256_hex;
use crate::domain::documents::document::{
    BacklinkInfo as DomainBacklink, Document as DomainDocument, OutgoingLink as DomainOutgoingLink,
    SearchHit,
};
use crate::domain::documents::{delete_plan, hierarchy, path as doc_path, policy as doc_policy};
use crate::domain::documents::permissions as doc_permissions;
use crate::domain::documents::policy::{DocumentPolicyError, DocumentState};
use crate::domain::documents::title;
use crate::domain::workspaces::permissions::PermissionSet;
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
        workspace_id: Uuid,
        query: Option<String>,
        tag: Option<String>,
        state: DocumentListFilter,
    ) -> Result<Vec<DomainDocument>, ServiceError> {
        let uc = ListDocuments {
            repo: self.document_repo.as_ref(),
        };
        uc.execute(workspace_id, query, tag, to_repo_state(state))
            .await
            .map_err(ServiceError::from)
    }

    pub async fn create_for_user(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        title: &str,
        parent_id: Option<Uuid>,
        doc_type: &str,
        created_by_plugin: Option<&str>,
    ) -> Result<DomainDocument, ServiceError> {
        doc_permissions::ensure_can_create(permissions, doc_type)
            .map_err(|_| ServiceError::Forbidden)?;
        if let Some(parent_id) = parent_id {
            self.ensure_active_parent(workspace_id, parent_id).await?;
        }
        let uc = CreateDocument {
            repo: self.document_repo.as_ref(),
        };
        let mut tx = self.begin_transaction().await?;
        let doc = match uc
            .execute_tx(
                &mut tx,
                workspace_id,
                actor_id,
                title,
                parent_id,
                doc_type,
                created_by_plugin,
            )
            .await
        {
            Ok(doc) => doc,
            Err(err) => {
                if err.downcast_ref::<DocumentPathConflictError>().is_some() {
                    tx.rollback().await.ok();
                    return Err(ServiceError::Conflict);
                }
                error!(error = ?err, "document_create_repo_failed");
                tx.rollback().await.ok();
                return Err(ServiceError::from(err));
            }
        };
        self.enqueue_projection_for_document_tx(&mut tx, &doc, "create_document")
            .await?;
        let repo_path = doc.desired_path.clone();
        let event_payload = json!({
            "title": doc.title,
            "parent_id": doc.parent_id,
            "doc_type": doc.doc_type,
            "repo_path": repo_path,
            "slug": doc.slug,
            "desired_path": doc.desired_path,
            "owner_id": doc.workspace_id,
            "actor_id": actor_id,
        });
        tx.commit().await.map_err(map_sqlx_error)?;
        self.record_event(
            doc.workspace_id,
            doc.id,
            "document.created",
            Some(event_payload),
        )
        .await;
        Ok(doc)
    }

    pub async fn duplicate_document(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> Result<DomainDocument, ServiceError> {
        let actor = Actor::User(actor_id);
        access::require_view(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            &actor,
            source_id,
        )
        .await
        .map_err(|_| ServiceError::Forbidden)?;

        let source = self
            .document_repo
            .get_by_id(source_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        if source.workspace_id != workspace_id {
            return Err(ServiceError::NotFound);
        }
        if source.doc_type == "folder" {
            return Err(ServiceError::BadRequest("cannot_duplicate_folder"));
        }

        let target_parent = match parent_id {
            Some(explicit) => explicit,
            None => source.parent_id.or(source.archived_parent_id),
        };

        let source_content = self
            .realtime
            .get_content(&source_id.to_string())
            .await
            .map_err(ServiceError::from)?
            .unwrap_or_default();

        let attachments = self.snapshot_attachments(source.id).await?;
        let new_title = title::duplicate_title(&source.title, title);
        let new_doc = self
            .create_for_user(
                workspace_id,
                actor_id,
                permissions,
                &new_title,
                target_parent,
                &source.doc_type,
                source.created_by_plugin.as_deref(),
            )
            .await?;

        let result = async {
            let updated_doc = self
                .update_content(&actor, new_doc.id, &source_content)
                .await?;

            self.copy_attachments(&updated_doc, &attachments, actor_id)
                .await?;

            Ok::<_, ServiceError>(updated_doc)
        }
        .await;

        match result {
            Ok(doc) => Ok(doc),
            Err(err) => {
                if let Err(clean_err) = self
                    .delete_for_user_internal(
                        workspace_id,
                        new_doc.id,
                        Some(actor_id),
                        permissions,
                        false,
                    )
                    .await
                {
                    warn!(
                        document_id = %new_doc.id,
                        error = ?clean_err,
                        "duplicate_cleanup_failed"
                    );
                }
                Err(err)
            }
        }
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

    pub async fn delete_for_user(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Option<Uuid>,
        permissions: &PermissionSet,
    ) -> Result<bool, ServiceError> {
        self.delete_for_user_internal(workspace_id, doc_id, actor_id, permissions, true)
            .await
    }

    async fn delete_for_user_internal(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Option<Uuid>,
        permissions: &PermissionSet,
        enforce_permissions: bool,
    ) -> Result<bool, ServiceError> {
        let mut tx = self.begin_transaction().await?;
        let root_meta = self
            .document_repo
            .get_meta_for_owner_tx(&mut tx, doc_id, workspace_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        if enforce_permissions {
            doc_permissions::ensure_can_delete(permissions, &root_meta.doc_type)
                .map_err(|_| ServiceError::Forbidden)?;
        }
        let delete_plan = self
            .build_delete_plan(&mut tx, doc_id, workspace_id, root_meta.clone())
            .await?;
        if delete_plan.is_empty() {
            tx.rollback().await.map_err(map_sqlx_error)?;
            return Ok(false);
        }
        let permission_snapshot = if enforce_permissions {
            permissions.to_vec()
        } else {
            // Cleanup flows (e.g., duplicate rollback) bypass user permissions so storage delete
            // jobs always have authority to remove docs and attachments.
            PermissionSet::all().to_vec()
        };
        let uc = DeleteDocument {
            repo: self.document_repo.as_ref(),
        };
        let mut deleted = false;
        let mut delete_events = Vec::new();
        for entry in delete_plan {
            if uc
                .execute_tx(&mut tx, entry.doc_id, workspace_id)
                .await
                .map_err(ServiceError::from)?
                .is_some()
            {
                deleted = true;
                self.enqueue_delete_job_for_entry(
                    &mut tx,
                    workspace_id,
                    &entry,
                    &permission_snapshot,
                    actor_id,
                )
                .await?;
                delete_events.push(entry.clone());
            }
        }
        if deleted {
            tx.commit().await.map_err(map_sqlx_error)?;
            for entry in delete_events {
                self.record_delete_event(workspace_id, &entry, actor_id)
                    .await;
            }
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
        self.enqueue_doc_sync_tx(&mut tx, doc.workspace_id, doc.id, "update_content")
            .await?;
        let repo_path = doc.desired_path.clone();
        let event_payload = json!({
            "repo_path": repo_path,
            "desired_path": doc.desired_path,
            "slug": doc.slug,
            "doc_type": doc.doc_type,
            "owner_id": doc.workspace_id,
        });
        tx.commit().await.map_err(map_sqlx_error)?;
        self.record_event(
            doc.workspace_id,
            doc.id,
            "document.content_updated",
            Some(event_payload),
        )
        .await;
        Ok(doc)
    }

    pub async fn patch_content(
        &self,
        actor: &Actor,
        doc_id: Uuid,
        operations: &[DocumentPatchOperation],
    ) -> Result<DomainDocument, ServiceError> {
        if operations.is_empty() {
            return Err(ServiceError::BadRequest("patch_operations_required"));
        }

        access::require_edit(
            self.access_repo.as_ref(),
            self.share_access.as_ref(),
            actor,
            doc_id,
        )
        .await
        .map_err(|_| ServiceError::Unauthorized)?;

        let current = self
            .realtime
            .get_content(&doc_id.to_string())
            .await
            .map_err(ServiceError::from)?
            .unwrap_or_default();
        let updated = apply_patch_operations(&current, operations)?;

        self.update_content(actor, doc_id, &updated).await
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
            .map_err(|err| {
                if err
                    .downcast_ref::<FolderDownloadUnsupportedFormat>()
                    .is_some()
                {
                    ServiceError::BadRequest("folder_archive_only")
                } else {
                    ServiceError::from(err)
                }
            })?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn download_workspace_root(
        &self,
        actor: &Actor,
        workspace_id: Uuid,
        workspace_name: &str,
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
        uc.download_workspace_root(actor, workspace_id, workspace_name, format)
            .await
            .map_err(|err| {
                if err
                    .downcast_ref::<FolderDownloadUnsupportedFormat>()
                    .is_some()
                {
                    ServiceError::BadRequest("folder_archive_only")
                } else {
                    ServiceError::from(err)
                }
            })?
            .ok_or(ServiceError::NotFound)
    }

    pub async fn update_metadata(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
        title: Option<String>,
        parent_id: Option<Option<Uuid>>,
    ) -> Result<DomainDocument, ServiceError> {
        let meta = self.load_owner_meta(workspace_id, doc_id).await?;
        let state = DocumentState::new(&meta.doc_type, meta.archived_at);
        let rename_requested = title.is_some();
        let move_requested = parent_id.is_some();
        if rename_requested {
            doc_policy::ensure_editable(state, permissions).map_err(map_policy_error)?;
        }
        if move_requested {
            doc_policy::ensure_movable(state, permissions).map_err(map_policy_error)?;
        }
        if let Some(Some(parent)) = parent_id {
            self.ensure_active_parent(workspace_id, parent).await?;
        }
        let previous_repo_path =
            doc_path::workspace_repo_relative(workspace_id, meta.path.as_deref());
        let uc = UpdateDocument {
            repo: self.document_repo.as_ref(),
        };
        let mut tx = self.begin_transaction().await?;
        let doc = match uc
            .execute_tx(&mut tx, doc_id, workspace_id, title, parent_id)
            .await
        {
            Ok(Some(doc)) => doc,
            Ok(None) => {
                tx.rollback().await.ok();
                return Err(ServiceError::NotFound);
            }
            Err(err) => {
                if err.downcast_ref::<DocumentPathConflictError>().is_some() {
                    tx.rollback().await.ok();
                    return Err(ServiceError::Conflict);
                }
                error!(error = ?err, "document_update_repo_failed");
                return Err(ServiceError::from(err));
            }
        };
        self.enqueue_projection_for_document_tx(&mut tx, &doc, "update_metadata")
            .await?;
        let repo_path = doc.desired_path.clone();
        let event_payload = json!({
            "title": doc.title,
            "parent_id": doc.parent_id,
            "repo_path": repo_path,
            "doc_type": doc.doc_type,
            "slug": doc.slug,
            "desired_path": doc.desired_path,
            "owner_id": doc.workspace_id,
            "actor_id": actor_id,
            "previous_path": previous_repo_path,
            "previous_desired_path": meta.desired_path,
        });
        tx.commit().await.map_err(map_sqlx_error)?;
        self.record_event(
            doc.workspace_id,
            doc.id,
            "document.metadata_updated",
            Some(event_payload),
        )
        .await;
        Ok(doc)
    }

    pub async fn archive_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<DomainDocument, ServiceError> {
        let meta = self.load_owner_meta(workspace_id, doc_id).await?;
        let state = DocumentState::new(&meta.doc_type, meta.archived_at);
        doc_policy::ensure_archivable(state, permissions).map_err(map_policy_error)?;
        let previous_repo_path =
            doc_path::workspace_repo_relative(workspace_id, meta.path.as_deref());
        let uc = ArchiveDocument {
            repo: self.document_repo.as_ref(),
            realtime: self.realtime.as_ref(),
        };
        let mut tx = self.begin_transaction().await?;
        let doc = uc
            .execute_tx(&mut tx, workspace_id, doc_id, actor_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        self.enqueue_projection_for_document_tx(&mut tx, &doc, "archive_document")
            .await?;
        let repo_path = doc.desired_path.clone();
        let event_payload = json!({
            "repo_path": repo_path,
            "doc_type": doc.doc_type,
            "slug": doc.slug,
            "desired_path": doc.desired_path,
            "owner_id": doc.workspace_id,
            "actor_id": actor_id,
            "previous_path": previous_repo_path,
            "previous_desired_path": meta.desired_path,
        });
        tx.commit().await.map_err(map_sqlx_error)?;
        self.record_event(
            doc.workspace_id,
            doc.id,
            "document.archived",
            Some(event_payload),
        )
        .await;
        Ok(doc)
    }

    pub async fn unarchive_document(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Uuid,
        permissions: &PermissionSet,
    ) -> Result<DomainDocument, ServiceError> {
        let meta = self.load_owner_meta(workspace_id, doc_id).await?;
        let state = DocumentState::new(&meta.doc_type, meta.archived_at);
        doc_policy::ensure_unarchivable(state, permissions).map_err(map_policy_error)?;
        let previous_repo_path =
            doc_path::workspace_repo_relative(workspace_id, meta.path.as_deref());
        let uc = UnarchiveDocument {
            repo: self.document_repo.as_ref(),
            realtime: self.realtime.as_ref(),
        };
        let mut tx = self.begin_transaction().await?;
        let doc = uc
            .execute_tx(&mut tx, workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        self.enqueue_projection_for_document_tx(&mut tx, &doc, "unarchive_document")
            .await?;
        let repo_path = doc.desired_path.clone();
        let event_payload = json!({
            "repo_path": repo_path,
            "doc_type": doc.doc_type,
            "slug": doc.slug,
            "desired_path": doc.desired_path,
            "owner_id": doc.workspace_id,
            "actor_id": actor_id,
            "previous_path": previous_repo_path,
            "previous_desired_path": meta.desired_path,
        });
        tx.commit().await.map_err(map_sqlx_error)?;
        self.record_event(
            doc.workspace_id,
            doc.id,
            "document.unarchived",
            Some(event_payload),
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
        workspace_id: Uuid,
        query: Option<String>,
        limit: i64,
    ) -> Result<Vec<SearchHit>, ServiceError> {
        let uc = SearchDocuments {
            repo: self.document_repo.as_ref(),
        };
        uc.execute(workspace_id, query, limit)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn backlinks(
        &self,
        actor: &Actor,
        workspace_id: Uuid,
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
        uc.execute(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn outgoing_links(
        &self,
        actor: &Actor,
        workspace_id: Uuid,
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
        uc.execute(workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)
    }

    async fn snapshot_attachments(
        &self,
        doc_id: Uuid,
    ) -> Result<Vec<AttachmentSnapshot>, ServiceError> {
        let files = self
            .files_repo
            .list_files_for_document(doc_id)
            .await
            .map_err(ServiceError::from)?;
        let mut snapshots = Vec::new();
        for file in files {
            let abs_path = self.storage.absolute_from_relative(&file.storage_path);
            let exists = self
                .storage
                .exists(&abs_path)
                .await
                .map_err(ServiceError::from)?;
            if !exists {
                warn!(
                    document_id = %doc_id,
                    storage_path = %file.storage_path,
                    "duplicate_attachment_missing"
                );
                continue;
            }
            let bytes = self
                .storage
                .read_bytes(&abs_path)
                .await
                .map_err(ServiceError::from)?;
            let content_hash = hash_bytes(&bytes);
            snapshots.push(AttachmentSnapshot {
                filename: file.filename,
                content_type: file.content_type,
                bytes,
                content_hash,
            });
        }
        Ok(snapshots)
    }

    async fn copy_attachments(
        &self,
        target_doc: &DomainDocument,
        attachments: &[AttachmentSnapshot],
        actor_id: Uuid,
    ) -> Result<(), ServiceError> {
        if attachments.is_empty() {
            return Ok(());
        }
        let base_dir = self
            .storage
            .build_doc_dir(target_doc.id)
            .await
            .map_err(ServiceError::from)?;
        for attachment in attachments {
            let filename = Path::new(&attachment.filename)
                .file_name()
                .and_then(|f| f.to_str())
                .map(str::to_string)
                .filter(|f| !f.is_empty())
                .unwrap_or_else(|| attachment.filename.clone());
            let target_path = base_dir.join("attachments").join(&filename);
            self.storage
                .write_bytes(&target_path, &attachment.bytes)
                .await
                .map_err(ServiceError::from)?;
            let storage_path = self
                .storage
                .relative_from_uploads(&target_path)
                .replace('\\', "/");
            self.files_repo
                .insert_file(
                    target_doc.id,
                    &filename,
                    attachment.content_type.as_deref(),
                    attachment.bytes.len() as i64,
                    &storage_path,
                    &attachment.content_hash,
                )
                .await
                .map_err(ServiceError::from)?;
            if let Some(repo_path) =
                doc_path::repo_relative_from_storage(target_doc.workspace_id, &storage_path)
            {
                let payload = json!({
                    "repo_path": repo_path,
                    "storage_path": storage_path,
                    "backend": "api",
                    "size": attachment.bytes.len() as i64,
                    "content_hash": attachment.content_hash,
                    "workspace_id": target_doc.workspace_id.to_string(),
                    "actor_id": actor_id.to_string(),
                });
                self.record_event(
                    target_doc.workspace_id,
                    target_doc.id,
                    "attachment.ingest_upsert",
                    Some(payload),
                )
                .await;
            }
        }
        Ok(())
    }

    async fn ensure_active_parent(
        &self,
        workspace_id: Uuid,
        parent_id: Uuid,
    ) -> Result<(), ServiceError> {
        let meta = self
            .document_repo
            .get_meta_for_owner(parent_id, workspace_id)
            .await
            .map_err(ServiceError::from)?;
        hierarchy::ensure_active_parent(meta.map(|m| hierarchy::ParentMeta {
            archived_at: m.archived_at,
        }))
        .map_err(map_parent_error)
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

    async fn enqueue_projection_for_document_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc: &DomainDocument,
        reason: &'static str,
    ) -> Result<(), ServiceError> {
        if doc.doc_type == "folder" {
            self.enqueue_folder_sync_tx(tx, doc.workspace_id, doc.id, reason)
                .await
        } else {
            self.enqueue_doc_sync_tx(tx, doc.workspace_id, doc.id, reason)
                .await
        }
    }

    async fn enqueue_doc_sync_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        doc_id: Uuid,
        reason: &'static str,
    ) -> Result<(), ServiceError> {
        let encoded_reason = serde_json::to_string(&StorageJobReason {
            reason: reason.to_string(),
            metadata: Some(WorkspaceJobMetadata { workspace_id }),
        })
        .ok();
        self.storage_jobs
            .enqueue_doc_job_tx(
                tx,
                workspace_id,
                doc_id,
                StorageProjectionJobKind::DocSync,
                encoded_reason.as_deref(),
            )
            .await
            .map_err(|err| {
                warn!(
                    error = ?err,
                    doc_id = %doc_id,
                    "storage_projection_enqueue_failed"
                );
                ServiceError::Unexpected(err)
            })
    }

    async fn enqueue_doc_delete_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        doc_id: Uuid,
        reason: &'static str,
        metadata: Option<StorageDeleteJobMetadata>,
    ) -> Result<(), ServiceError> {
        let encoded_reason = metadata.and_then(|meta| {
            serde_json::to_string(&StorageJobReason {
                reason: reason.to_string(),
                metadata: Some(meta),
            })
            .ok()
        });
        let reason_str = encoded_reason.as_deref().unwrap_or(reason);
        self.storage_jobs
            .enqueue_doc_job_tx(
                tx,
                workspace_id,
                doc_id,
                StorageProjectionJobKind::DeleteDoc,
                Some(reason_str),
            )
            .await
            .map_err(|err| {
                warn!(
                    error = ?err,
                    doc_id = %doc_id,
                    "storage_projection_enqueue_failed"
                );
                ServiceError::Unexpected(err)
            })
    }

    async fn enqueue_folder_sync_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        folder_id: Uuid,
        reason: &'static str,
    ) -> Result<(), ServiceError> {
        self.storage_jobs
            .enqueue_folder_job_tx(
                tx,
                workspace_id,
                folder_id,
                StorageProjectionJobKind::FolderSync,
                Some(reason),
            )
            .await
            .map_err(|err| {
                warn!(
                    error = ?err,
                    folder_id = %folder_id,
                    "storage_projection_enqueue_failed"
                );
                ServiceError::Unexpected(err)
            })
    }

    async fn enqueue_folder_delete_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        folder_id: Uuid,
        reason: &'static str,
        metadata: Option<StorageDeleteJobMetadata>,
    ) -> Result<(), ServiceError> {
        let encoded_reason = metadata.and_then(|meta| {
            serde_json::to_string(&StorageJobReason {
                reason: reason.to_string(),
                metadata: Some(meta),
            })
            .ok()
        });
        let reason_str = encoded_reason.as_deref().unwrap_or(reason);
        self.storage_jobs
            .enqueue_folder_job_tx(
                tx,
                workspace_id,
                folder_id,
                StorageProjectionJobKind::DeleteFolder,
                Some(reason_str),
            )
            .await
            .map_err(|err| {
                warn!(
                    error = ?err,
                    folder_id = %folder_id,
                    "storage_projection_enqueue_failed"
                );
                ServiceError::Unexpected(err)
            })
    }

    async fn record_event(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        event_type: &'static str,
        payload: Option<serde_json::Value>,
    ) {
        if let Err(err) = self
            .events
            .append(workspace_id, doc_id, event_type, payload)
            .await
        {
            warn!(
                error = ?err,
                doc_id = %doc_id,
                event_type,
                "doc_event_log_append_failed"
            );
        }
    }

    async fn build_delete_plan(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        doc_id: Uuid,
        workspace_id: Uuid,
        root_meta: DocMeta,
    ) -> Result<Vec<delete_plan::DeleteEntry>, ServiceError> {
        let subtree = self
            .document_repo
            .list_owned_subtree_documents_tx(tx, workspace_id, doc_id)
            .await
            .map_err(ServiceError::from)?;

        let mut nodes = Vec::new();
        for node in subtree {
            let meta = if node.id == doc_id {
                root_meta.clone()
            } else {
                self.document_repo
                    .get_meta_for_owner_tx(tx, node.id, workspace_id)
                    .await
                    .map_err(ServiceError::from)?
                    .ok_or(ServiceError::NotFound)?
            };
            let attachments = if node.doc_type != "folder" {
                self.files_repo
                    .list_storage_paths_for_document_tx(tx, node.id)
                    .await
                    .map_err(ServiceError::from)?
            } else {
                Vec::new()
            };
            nodes.push(delete_plan::DeleteNode {
                id: node.id,
                doc_type: node.doc_type,
                meta,
                attachments,
            });
        }

        let entries = delete_plan::build_delete_plan(doc_id, root_meta, nodes).map_err(|err| {
            error!(error = ?err, "build_delete_entries_failed");
            ServiceError::Unexpected(err.into())
        })?;
        Ok(entries)
    }

    async fn enqueue_delete_job_for_entry(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        workspace_id: Uuid,
        entry: &delete_plan::DeleteEntry,
        permission_snapshot: &[String],
        actor_id: Option<Uuid>,
    ) -> Result<(), ServiceError> {
        let repo_path = doc_path::workspace_repo_relative(workspace_id, entry.meta.path.as_deref())
            .unwrap_or_else(|| entry.meta.desired_path.clone());
        let metadata = StorageDeleteJobMetadata {
            workspace_id,
            repo_path: Some(repo_path),
            doc_type: entry.doc_type.clone(),
            attachment_paths: if entry.attachments.is_empty() {
                None
            } else {
                Some(entry.attachments.clone())
            },
            permission_snapshot: permission_snapshot.to_vec(),
            actor_id,
        };
        if entry.doc_type == "folder" {
            self.enqueue_folder_delete_tx(
                tx,
                workspace_id,
                entry.doc_id,
                entry.reason,
                Some(metadata),
            )
            .await
        } else {
            self.enqueue_doc_delete_tx(tx, workspace_id, entry.doc_id, entry.reason, Some(metadata))
                .await
        }
    }

    async fn record_delete_event(
        &self,
        workspace_id: Uuid,
        entry: &delete_plan::DeleteEntry,
        actor_id: Option<Uuid>,
    ) {
        let repo_path = doc_path::workspace_repo_relative(workspace_id, entry.meta.path.as_deref())
            .unwrap_or_else(|| entry.meta.desired_path.clone());
        let previous_repo_path =
            doc_path::workspace_repo_relative(workspace_id, entry.meta.path.as_deref());
        let mut payload = json!({
            "doc_type": entry.doc_type,
            "repo_path": repo_path,
            "slug": entry.meta.slug,
            "desired_path": entry.meta.desired_path,
            "owner_id": workspace_id,
            "previous_path": previous_repo_path,
        });
        if let Some(actor) = actor_id {
            if let serde_json::Value::Object(ref mut map) = payload {
                map.insert("actor_id".into(), json!(actor));
            }
        }
        self.record_event(
            workspace_id,
            entry.doc_id,
            "document.deleted",
            Some(payload),
        )
        .await;
    }
}

#[derive(Debug, Clone)]
pub enum DocumentPatchOperation {
    Insert { offset: usize, text: String },
    Delete { offset: usize, length: usize },
    Replace { offset: usize, length: usize, text: String },
}

#[derive(Debug, Clone)]
struct AttachmentSnapshot {
    filename: String,
    content_type: Option<String>,
    bytes: Vec<u8>,
    content_hash: String,
}

fn apply_patch_operations(
    initial: &str,
    operations: &[DocumentPatchOperation],
) -> Result<String, ServiceError> {
    let mut chars: Vec<char> = initial.chars().collect();
    for operation in operations {
        match operation {
            DocumentPatchOperation::Insert { offset, text } => {
                splice_chars(&mut chars, *offset, 0, text)?;
            }
            DocumentPatchOperation::Delete { offset, length } => {
                splice_chars(&mut chars, *offset, *length, "")?;
            }
            DocumentPatchOperation::Replace {
                offset,
                length,
                text,
            } => {
                splice_chars(&mut chars, *offset, *length, text)?;
            }
        }
    }
    Ok(chars.into_iter().collect())
}

fn splice_chars(
    chars: &mut Vec<char>,
    offset: usize,
    length: usize,
    replacement: &str,
) -> Result<(), ServiceError> {
    if offset > chars.len() {
        return Err(ServiceError::BadRequest("patch_offset_out_of_bounds"));
    }
    let end = offset
        .checked_add(length)
        .ok_or(ServiceError::BadRequest("patch_length_overflow"))?;
    if end > chars.len() {
        return Err(ServiceError::BadRequest("patch_range_out_of_bounds"));
    }
    chars.splice(offset..end, replacement.chars());
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    sha256_hex(bytes)
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

fn map_policy_error(err: DocumentPolicyError) -> ServiceError {
    match err {
        DocumentPolicyError::Forbidden => ServiceError::Forbidden,
        DocumentPolicyError::Archived | DocumentPolicyError::NotArchived => ServiceError::Conflict,
        DocumentPolicyError::FolderNotSupported => {
            ServiceError::BadRequest("operation_not_supported_for_folder")
        }
    }
}

fn map_parent_error(err: hierarchy::ParentValidationError) -> ServiceError {
    match err {
        hierarchy::ParentValidationError::NotFound => ServiceError::NotFound,
        hierarchy::ParentValidationError::Archived => ServiceError::Conflict,
    }
}

fn map_sqlx_error(err: sqlx::Error) -> ServiceError {
    error!(error = ?err, "document_sql_error");
    ServiceError::Unexpected(err.into())
}
