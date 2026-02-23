//! Update document command
//!
//! Updates document metadata with RBAC permission check.

use domain::document::{DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{WorkspaceMemberRepository, WorkspaceRolePermissionRepository, WorkspaceRoleRepository, permission};
use std::sync::Arc;

use crate::dto::DocumentDto;
use crate::util::document_validation::{encrypted_title_fields_valid, validate_parent_document};
use crate::util::workspace_access::{WorkspaceAccessError, load_document_with_permission};
use thiserror::Error;

/// Update document command
#[derive(Debug)]
pub struct UpdateDocumentCommand {
    pub document_id: DocumentId,
    pub user_id: UserId,
    /// New title (optional)
    pub title: Option<String>,
    /// New encrypted title (optional)
    pub encrypted_title: Option<Vec<u8>>,
    pub encrypted_title_nonce: Option<Vec<u8>>,
    /// New parent ID (optional, None means no change, Some(None) means move to root)
    pub parent_id: Option<Option<DocumentId>>,
}

/// Update document result
#[derive(Debug)]
pub struct UpdateDocumentResult {
    pub document: DocumentDto,
}

/// Update document error
#[derive(Debug, Error)]
pub enum UpdateDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error> {
    #[error("document not found")]
    DocumentNotFound,

    #[error("document is archived and cannot be modified")]
    DocumentArchived,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("parent document not found")]
    ParentNotFound,

    #[error("parent is not a folder")]
    ParentNotFolder,

    #[error("parent document is archived")]
    ParentArchived,

    #[error("cannot move document to itself or its descendant")]
    CircularReference,

    #[error("encrypted_title and encrypted_title_nonce must both be provided or both omitted")]
    InvalidEncryptedTitleFields,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    UpdateDocumentError<DR, MR, RR, RPR>,
    not_found: [
        UpdateDocumentError::DocumentNotFound,
        UpdateDocumentError::ParentNotFound,
        UpdateDocumentError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        UpdateDocumentError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
    invalid_input: [
        UpdateDocumentError::ParentNotFolder,
        UpdateDocumentError::CircularReference,
        UpdateDocumentError::InvalidEncryptedTitleFields,
    ],
    conflict: [
        UpdateDocumentError::DocumentArchived,
        UpdateDocumentError::ParentArchived,
    ],
);

crate::util::workspace_access::impl_from_load_doc_perm!([DR, MR, RR, RPR] UpdateDocumentError<DR, MR, RR, RPR>);

crate::util::document_validation::impl_from_parent_validation!(
    [DR, MR, RR, RPR] UpdateDocumentError<DR, MR, RR, RPR>
);

/// Update document handler
pub struct UpdateDocumentHandler<DR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
}

impl<DR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> UpdateDocumentHandler<DR, MR, RR, RPR>
where
    DR: DocumentRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
{
    pub fn new(document_repo: Arc<DR>, member_repo: Arc<MR>, role_repo: Arc<RR>, role_perm_repo: Arc<RPR>) -> Self {
        Self {
            document_repo,
            member_repo,
            role_repo,
            role_perm_repo,
        }
    }

    pub async fn handle(
        &self,
        command: UpdateDocumentCommand,
    ) -> Result<UpdateDocumentResult, UpdateDocumentError<DR::Error, MR::Error, RR::Error, RPR::Error>> {
        let mut document = load_document_with_permission(
            &self.document_repo,
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.document_id,
            command.user_id,
            permission::DOCUMENT_WRITE,
        )
        .await
        .map_err(UpdateDocumentError::from_load)?;

        if document.is_archived() {
            return Err(UpdateDocumentError::DocumentArchived);
        }

        // Validate encrypted title fields (must have both or neither)
        if !encrypted_title_fields_valid(&command.encrypted_title, &command.encrypted_title_nonce) {
            return Err(UpdateDocumentError::InvalidEncryptedTitleFields);
        }

        // 6. Update title if provided
        if let Some(title) = command.title {
            document.set_title(title);
        }

        // 7. Update encrypted title if provided
        if let Some(encrypted_title) = command.encrypted_title {
            let nonce = command.encrypted_title_nonce.expect("validated: nonce required with encrypted_title");
            document.set_encrypted_title(encrypted_title, nonce);
        }

        // 8. Update parent if provided
        if let Some(new_parent_id) = command.parent_id {
            self.validate_and_apply_parent_move(&mut document, new_parent_id)
                .await?;
        }

        // 9. Save document
        self.document_repo
            .save(&document)
            .await
            .map_err(UpdateDocumentError::DocumentRepository)?;

        Ok(UpdateDocumentResult { document: document.into() })
    }

    /// Validate and apply a parent move for a document.
    async fn validate_and_apply_parent_move(
        &self,
        document: &mut domain::document::Document,
        new_parent_id: Option<DocumentId>,
    ) -> Result<(), UpdateDocumentError<DR::Error, MR::Error, RR::Error, RPR::Error>> {
        if let Some(parent_id) = new_parent_id {
            // Basic parent validation (exists, is folder, not archived, same workspace)
            validate_parent_document(&*self.document_repo, parent_id, document.workspace_id)
                .await
                .map_err(UpdateDocumentError::from_parent_validation)?;

            // Circular reference checks (specific to move operations)
            if parent_id == document.id {
                return Err(UpdateDocumentError::CircularReference);
            }
            if document.is_folder()
                && self
                    .is_descendant(parent_id, document.id)
                    .await
                    .map_err(UpdateDocumentError::DocumentRepository)?
            {
                return Err(UpdateDocumentError::CircularReference);
            }

            document.set_parent(Some(parent_id));
        } else {
            document.set_parent(None);
        }
        Ok(())
    }

    /// Check if `potential_descendant` is a descendant of `ancestor_id`.
    ///
    /// Walks parent pointers up to a bounded depth to guard against
    /// corrupted circular parent_id chains.
    async fn is_descendant(
        &self,
        potential_descendant: DocumentId,
        ancestor_id: DocumentId,
    ) -> Result<bool, DR::Error> {
        const MAX_DEPTH: usize = 256;
        let mut current_id = Some(potential_descendant);
        let mut visited = std::collections::HashSet::new();

        while let Some(id) = current_id {
            if id == ancestor_id {
                return Ok(true);
            }
            if !visited.insert(id) || visited.len() > MAX_DEPTH {
                // Cycle detected or depth exceeded — treat as not a descendant
                return Ok(false);
            }

            let doc = self.document_repo.find_by_id(id).await?;
            current_id = doc.and_then(|d| d.parent_id);
        }

        Ok(false)
    }
}
