//! Update document command
//!
//! Updates document metadata with RBAC permission check.

use domain::document::{Document, DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository, can_perform,
};
use std::sync::Arc;
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
    pub document: Document,
}

/// Update document error
#[derive(Debug, Error)]
pub enum UpdateDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
    #[error("document not found")]
    DocumentNotFound,

    #[error("document is archived and cannot be modified")]
    DocumentArchived,

    #[error("user is not a member of this workspace")]
    NotMember,

    #[error("permission denied: cannot write to this workspace")]
    PermissionDenied,

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

    #[error("member repository error: {0}")]
    MemberRepository(MR),

    #[error("role repository error: {0}")]
    RoleRepository(RR),
}

impl<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error>
    UpdateDocumentError<DR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            UpdateDocumentError::DocumentNotFound | UpdateDocumentError::ParentNotFound
        )
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            UpdateDocumentError::NotMember | UpdateDocumentError::PermissionDenied
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            UpdateDocumentError::ParentNotFolder
                | UpdateDocumentError::CircularReference
                | UpdateDocumentError::InvalidEncryptedTitleFields
        )
    }

    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            UpdateDocumentError::DocumentArchived | UpdateDocumentError::ParentArchived
        )
    }
}

/// Update document handler
pub struct UpdateDocumentHandler<DR, MR, RR> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR, MR, RR> UpdateDocumentHandler<DR, MR, RR>
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
        command: UpdateDocumentCommand,
    ) -> Result<UpdateDocumentResult, UpdateDocumentError<DR::Error, MR::Error, RR::Error>> {
        // 1. Get document
        let mut document = self
            .document_repo
            .find_by_id(command.document_id)
            .await
            .map_err(UpdateDocumentError::DocumentRepository)?
            .ok_or(UpdateDocumentError::DocumentNotFound)?;

        // 2. Check if document is archived (archived documents cannot be modified)
        if document.is_archived() {
            return Err(UpdateDocumentError::DocumentArchived);
        }

        // 3. Check membership and get role
        let member = self
            .member_repo
            .find_by_workspace_and_user(document.workspace_id, command.user_id)
            .await
            .map_err(UpdateDocumentError::MemberRepository)?
            .ok_or(UpdateDocumentError::NotMember)?;

        // 4. Get role and check Write permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(UpdateDocumentError::RoleRepository)?
            .ok_or(UpdateDocumentError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Write) {
            return Err(UpdateDocumentError::PermissionDenied);
        }

        // 5. Validate encrypted title fields (must have both or neither)
        match (&command.encrypted_title, &command.encrypted_title_nonce) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(UpdateDocumentError::InvalidEncryptedTitleFields);
            }
            _ => {}
        }

        // 6. Update title if provided
        if let Some(title) = command.title {
            document.title = title;
            document.updated_at = chrono::Utc::now();
        }

        // 7. Update encrypted title if provided
        if let Some(encrypted_title) = command.encrypted_title {
            document.encrypted_title = Some(encrypted_title);
            document.encrypted_title_nonce = command.encrypted_title_nonce;
            document.is_encrypted = true;
            document.updated_at = chrono::Utc::now();
        }

        // 8. Update parent if provided
        if let Some(new_parent_id) = command.parent_id {
            if let Some(parent_id) = new_parent_id {
                // Validate parent exists and is a folder
                let parent = self
                    .document_repo
                    .find_by_id(parent_id)
                    .await
                    .map_err(UpdateDocumentError::DocumentRepository)?
                    .ok_or(UpdateDocumentError::ParentNotFound)?;

                if !parent.is_folder() {
                    return Err(UpdateDocumentError::ParentNotFolder);
                }

                // Check if parent is archived
                if parent.is_archived() {
                    return Err(UpdateDocumentError::ParentArchived);
                }

                // Check for circular reference (cannot move to self)
                if parent_id == command.document_id {
                    return Err(UpdateDocumentError::CircularReference);
                }

                // Check for circular reference (cannot move to descendant)
                if document.is_folder()
                    && self
                        .is_descendant(parent_id, command.document_id)
                        .await
                        .map_err(UpdateDocumentError::DocumentRepository)?
                {
                    return Err(UpdateDocumentError::CircularReference);
                }

                // Verify parent is in same workspace
                if parent.workspace_id != document.workspace_id {
                    return Err(UpdateDocumentError::ParentNotFound);
                }

                document.parent_id = Some(parent_id);
            } else {
                // Move to root
                document.parent_id = None;
            }
            document.updated_at = chrono::Utc::now();
        }

        // 9. Save document
        self.document_repo
            .save(&document)
            .await
            .map_err(UpdateDocumentError::DocumentRepository)?;

        Ok(UpdateDocumentResult { document })
    }

    /// Check if `potential_descendant` is a descendant of `ancestor_id`
    async fn is_descendant(
        &self,
        potential_descendant: DocumentId,
        ancestor_id: DocumentId,
    ) -> Result<bool, DR::Error> {
        let mut current_id = Some(potential_descendant);

        while let Some(id) = current_id {
            if id == ancestor_id {
                return Ok(true);
            }

            let doc = self.document_repo.find_by_id(id).await?;
            current_id = doc.and_then(|d| d.parent_id);
        }

        Ok(false)
    }
}
