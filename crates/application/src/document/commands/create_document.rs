//! Create document command
//!
//! Creates a new document in a workspace with RBAC permission check.

use domain::document::{Document, DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
};
use std::sync::Arc;
use thiserror::Error;

use crate::dto::DocumentDto;
use crate::util::document_validation::{encrypted_title_fields_valid, validate_parent_document};
use crate::util::slug::generate_slug;
use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};

/// Create document command
#[derive(Debug)]
pub struct CreateDocumentCommand {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub title: String,
    pub parent_id: Option<DocumentId>,
    /// Encrypted title (for E2EE documents)
    pub encrypted_title: Option<Vec<u8>>,
    pub encrypted_title_nonce: Option<Vec<u8>>,
    /// Is this a folder?
    pub is_folder: bool,
}

/// Create document result
#[derive(Debug)]
pub struct CreateDocumentResult {
    pub document: DocumentDto,
}

/// Create document error
#[derive(Debug, Error)]
pub enum CreateDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR>),

    #[error("parent document not found")]
    ParentNotFound,

    #[error("parent is not a folder")]
    ParentNotFolder,

    #[error("parent document is archived")]
    ParentArchived,

    #[error("slug already exists")]
    SlugExists,

    #[error("encrypted_title and encrypted_title_nonce must both be provided or both omitted")]
    InvalidEncryptedTitleFields,

    #[error("document repository error: {0}")]
    DocumentRepository(DR),
}

crate::types::impl_app_error!(
    [DR: std::error::Error, MR: std::error::Error, RR: std::error::Error]
    CreateDocumentError<DR, MR, RR>,
    not_found: [
        CreateDocumentError::ParentNotFound,
        CreateDocumentError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        CreateDocumentError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
    invalid_input: [
        CreateDocumentError::ParentNotFolder,
        CreateDocumentError::InvalidEncryptedTitleFields,
    ],
    conflict: [
        CreateDocumentError::SlugExists,
        CreateDocumentError::ParentArchived,
    ],
);

crate::util::document_validation::impl_from_parent_validation!(
    [DR, MR, RR] CreateDocumentError<DR, MR, RR>
);

/// Create document handler
pub struct CreateDocumentHandler<DR: ?Sized, MR: ?Sized, RR: ?Sized> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR: ?Sized, MR: ?Sized, RR: ?Sized> CreateDocumentHandler<DR, MR, RR>
where
    DR: DocumentRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
{
    pub fn new(document_repo: Arc<DR>, member_repo: Arc<MR>, role_repo: Arc<RR>) -> Self {
        Self {
            document_repo,
            member_repo,
            role_repo,
        }
    }

    pub async fn handle(
        &self,
        command: CreateDocumentCommand,
    ) -> Result<CreateDocumentResult, CreateDocumentError<DR::Error, MR::Error, RR::Error>> {
        // 1. Check membership and Write permission
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            command.workspace_id,
            command.user_id,
            WorkspacePermission::Write,
        )
        .await
        .map_err(CreateDocumentError::WorkspaceAccess)?;

        // 3. Validate encrypted title fields (must have both or neither)
        if !encrypted_title_fields_valid(&command.encrypted_title, &command.encrypted_title_nonce) {
            return Err(CreateDocumentError::InvalidEncryptedTitleFields);
        }

        // 4. Validate parent if provided
        if let Some(parent_id) = command.parent_id {
            validate_parent_document(&*self.document_repo, parent_id, command.workspace_id)
                .await
                .map_err(CreateDocumentError::from_parent_validation)?;
        }

        // 6. Generate slug from title
        let base_slug = generate_slug(&command.title);
        let slug = self
            .ensure_unique_slug(command.workspace_id, base_slug)
            .await?;

        // 7. Create document
        let document = if command.is_folder {
            Document::new_folder(
                command.workspace_id,
                command.title.clone(),
                slug,
                Some(command.user_id),
            )
        } else if let (Some(encrypted_title), Some(nonce)) =
            (command.encrypted_title, command.encrypted_title_nonce)
        {
            Document::new_encrypted(
                command.workspace_id,
                command.title.clone(),
                encrypted_title,
                nonce,
                slug,
                Some(command.user_id),
            )
        } else {
            Document::new(
                command.workspace_id,
                command.title.clone(),
                slug,
                Some(command.user_id),
            )
        };

        // Set parent if provided
        let document = if let Some(parent_id) = command.parent_id {
            document.with_parent(parent_id)
        } else {
            document
        };

        // 8. Save document
        self.document_repo
            .save(&document)
            .await
            .map_err(CreateDocumentError::DocumentRepository)?;

        Ok(CreateDocumentResult { document: document.into() })
    }

    async fn ensure_unique_slug(
        &self,
        workspace_id: WorkspaceId,
        base_slug: String,
    ) -> Result<String, CreateDocumentError<DR::Error, MR::Error, RR::Error>> {
        // Check if base slug is available
        let exists = self
            .document_repo
            .slug_exists(workspace_id, &base_slug)
            .await
            .map_err(CreateDocumentError::DocumentRepository)?;

        if !exists {
            return Ok(base_slug);
        }

        // Try with numeric suffixes
        for i in 1..100 {
            let slug = format!("{}-{}", base_slug, i);
            let exists = self
                .document_repo
                .slug_exists(workspace_id, &slug)
                .await
                .map_err(CreateDocumentError::DocumentRepository)?;

            if !exists {
                return Ok(slug);
            }
        }

        // Fallback: use UUID
        Ok(format!("{}-{}", base_slug, uuid::Uuid::now_v7()))
    }
}

