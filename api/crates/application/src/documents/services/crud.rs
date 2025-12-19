use serde_json::json;
use tracing::{error, warn};
use uuid::Uuid;

use domain::access::permissions::PermissionSet;
use domain::documents::document::{Document as DomainDocument, SearchHit};
use domain::documents::permissions as doc_permissions;
use domain::documents::policy::DocumentState;
use domain::documents::{hierarchy, path as doc_path, policy as doc_policy, title};

use crate::core::services::access::{self, Actor};
use crate::core::services::errors::ServiceError;
use crate::documents::dtos::DocumentListFilter;
use crate::documents::ports::tx_runner::run_in_tx;
use crate::documents::use_cases::create_document::CreateDocument;
use crate::documents::use_cases::delete_document::DeleteDocument;
use crate::documents::use_cases::get_document::GetDocument;
use crate::documents::use_cases::list_documents::ListDocuments;
use crate::documents::use_cases::search_documents::SearchDocuments;
use crate::documents::use_cases::update_document::UpdateDocument;

use super::DocumentService;
use super::util::{map_parent_error, map_policy_error, map_tx_error, to_repo_state};

impl DocumentService {
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
        doc_type: domain::documents::doc_type::DocumentType,
        created_by_plugin: Option<&str>,
    ) -> Result<DomainDocument, ServiceError> {
        doc_permissions::ensure_can_create(permissions, doc_type)
            .map_err(|_| ServiceError::Forbidden)?;
        let created_by_plugin = created_by_plugin.map(ToOwned::to_owned);
        let title = domain::documents::title::Title::from_user_input(title);
        let parent_desired_path = if let Some(parent_id) = parent_id {
            let meta = self.load_owner_meta(workspace_id, parent_id).await?;
            hierarchy::ensure_active_parent(Some(hierarchy::ParentMeta {
                archived_at: meta.archived_at,
            }))
            .map_err(map_parent_error)?;
            Some(meta.desired_path)
        } else {
            None
        };
        let doc = match run_in_tx(self.tx_runner.as_ref(), move |tx| {
            Box::pin(async move {
                let doc = {
                    let mut uc = CreateDocument {
                        repo: tx.documents(),
                    };
                    uc.execute(
                        workspace_id,
                        actor_id,
                        &title,
                        parent_id,
                        parent_desired_path.as_ref(),
                        doc_type,
                        created_by_plugin.as_deref(),
                    )
                    .await?
                };
                Self::enqueue_projection_for_document_tx(
                    tx.storage_jobs(),
                    &doc,
                    "create_document",
                )
                .await?;
                Ok(doc)
            })
        })
        .await
        {
            Ok(doc) => doc,
            Err(err) => {
                let service_err = map_tx_error(err);
                if service_err.is_internal() {
                    error!(error = ?service_err, "document_create_repo_failed");
                }
                return Err(service_err);
            }
        };
        let repo_path = doc.desired_path.as_str().to_string();
        let event_payload = json!({
            "title": doc.title.as_str(),
            "parent_id": doc.parent_id,
            "doc_type": doc.doc_type.as_str(),
            "repo_path": repo_path,
            "slug": doc.slug.as_str(),
            "desired_path": doc.desired_path.as_str(),
            "owner_id": doc.workspace_id,
            "actor_id": actor_id,
        });
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
        .await?;

        let source = self
            .document_repo
            .get_by_id(source_id)
            .await
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::NotFound)?;
        if source.workspace_id != workspace_id {
            return Err(ServiceError::NotFound);
        }
        let state = DocumentState::new(source.doc_type, source.archived_at);
        if doc_policy::ensure_duplicate_allowed(state).is_err() {
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
                new_title.as_str(),
                target_parent,
                source.doc_type,
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

    pub(super) async fn delete_for_user_internal(
        &self,
        workspace_id: Uuid,
        doc_id: Uuid,
        actor_id: Option<Uuid>,
        permissions: &PermissionSet,
        enforce_permissions: bool,
    ) -> Result<bool, ServiceError> {
        let root_meta = self.load_owner_meta(workspace_id, doc_id).await?;
        if enforce_permissions {
            doc_permissions::ensure_can_delete(permissions, root_meta.doc_type)
                .map_err(|_| ServiceError::Forbidden)?;
        }
        let permission_snapshot = if enforce_permissions {
            permissions.to_vec()
        } else {
            // Cleanup flows (e.g., duplicate rollback) bypass user permissions so storage delete
            // jobs always have authority to remove docs and attachments.
            PermissionSet::all().to_vec()
        };
        let (deleted, delete_events) = run_in_tx(self.tx_runner.as_ref(), move |tx| {
            Box::pin(async move {
                let delete_plan =
                    Self::build_delete_plan(tx, doc_id, workspace_id, root_meta.clone()).await?;
                if delete_plan.is_empty() {
                    return Ok((false, Vec::new()));
                }

                let mut deleted = false;
                let mut delete_events = Vec::new();
                for entry in delete_plan {
                    let deleted_type = {
                        let mut uc = DeleteDocument {
                            repo: tx.documents(),
                        };
                        uc.execute(entry.doc_id, workspace_id).await?
                    };
                    if deleted_type.is_some() {
                        deleted = true;
                        Self::enqueue_delete_job_for_entry(
                            tx,
                            workspace_id,
                            &entry,
                            &permission_snapshot,
                            actor_id,
                        )
                        .await?;
                        delete_events.push(entry.clone());
                    }
                }
                Ok((deleted, delete_events))
            })
        })
        .await
        .map_err(map_tx_error)?;

        if deleted {
            for entry in delete_events {
                self.record_delete_event(workspace_id, &entry, actor_id)
                    .await;
            }
        }
        Ok(deleted)
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
        let state = DocumentState::new(meta.doc_type, meta.archived_at);
        let requested_title = title
            .as_deref()
            .map(domain::documents::title::Title::from_user_input);
        let rename_requested = title.is_some();
        let move_requested = parent_id.is_some();
        if rename_requested {
            doc_policy::ensure_editable(state, permissions).map_err(map_policy_error)?;
        }
        if move_requested {
            doc_policy::ensure_movable(state, permissions).map_err(map_policy_error)?;
        }
        let parent_desired_path = match parent_id {
            Some(Some(parent)) => {
                let meta = self.load_owner_meta(workspace_id, parent).await?;
                hierarchy::ensure_active_parent(Some(hierarchy::ParentMeta {
                    archived_at: meta.archived_at,
                }))
                .map_err(map_parent_error)?;
                Some(meta.desired_path)
            }
            Some(None) => None,
            None => doc_path::parent_desired_path(&meta.desired_path),
        };
        let previous_repo_path =
            doc_path::workspace_repo_relative(workspace_id, meta.path.as_deref())
                .map(|p| p.into_string());
        let current_title = meta.title.clone();
        let current_slug = meta.slug.clone();
        let current_desired_path = meta.desired_path.clone();
        let current_doc_type = meta.doc_type;
        let previous_desired_path = meta.desired_path.as_str().to_string();
        let doc = match run_in_tx(self.tx_runner.as_ref(), move |tx| {
            Box::pin(async move {
                let doc = {
                    let mut uc = UpdateDocument {
                        repo: tx.documents(),
                    };
                    uc.execute(
                        doc_id,
                        workspace_id,
                        &current_title,
                        &current_slug,
                        &current_desired_path,
                        current_doc_type,
                        requested_title.as_ref(),
                        parent_id,
                        parent_desired_path.as_ref(),
                    )
                    .await?
                };
                let Some(doc) = doc else {
                    return Err(ServiceError::NotFound.into());
                };
                Self::enqueue_projection_for_document_tx(
                    tx.storage_jobs(),
                    &doc,
                    "update_metadata",
                )
                .await?;
                Ok(doc)
            })
        })
        .await
        {
            Ok(doc) => doc,
            Err(err) => {
                let service_err = map_tx_error(err);
                if service_err.is_internal() {
                    error!(error = ?service_err, "document_update_repo_failed");
                }
                return Err(service_err);
            }
        };
        let repo_path = doc.desired_path.as_str().to_string();
        let event_payload = json!({
            "title": doc.title.as_str(),
            "parent_id": doc.parent_id,
            "repo_path": repo_path,
            "doc_type": doc.doc_type.as_str(),
            "slug": doc.slug.as_str(),
            "desired_path": doc.desired_path.as_str(),
            "owner_id": doc.workspace_id,
            "actor_id": actor_id,
            "previous_path": previous_repo_path,
            "previous_desired_path": previous_desired_path,
        });
        self.record_event(
            doc.workspace_id,
            doc.id,
            "document.metadata_updated",
            Some(event_payload),
        )
        .await;
        Ok(doc)
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
}
