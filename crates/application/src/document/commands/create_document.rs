//! Create document command
//!
//! Creates a new document in a workspace with RBAC permission check.

use std::sync::Arc;
use domain::document::{Document, DocumentId, DocumentRepository};
use domain::identity::UserId;
use domain::workspace::{
    WorkspaceId, WorkspaceMemberRepository, WorkspacePermission, WorkspaceRoleRepository,
    can_perform,
};
use thiserror::Error;

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
    pub document: Document,
}

/// Create document error
#[derive(Debug, Error)]
pub enum CreateDocumentError<DR: std::error::Error, MR: std::error::Error, RR: std::error::Error> {
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

    #[error("slug already exists")]
    SlugExists,

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
    CreateDocumentError<DR, MR, RR>
{
    pub fn is_not_found(&self) -> bool {
        matches!(self, CreateDocumentError::ParentNotFound)
    }

    pub fn is_forbidden(&self) -> bool {
        matches!(
            self,
            CreateDocumentError::NotMember | CreateDocumentError::PermissionDenied
        )
    }

    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            CreateDocumentError::SlugExists | CreateDocumentError::ParentArchived
        )
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            CreateDocumentError::ParentNotFolder | CreateDocumentError::InvalidEncryptedTitleFields
        )
    }
}

/// Create document handler
pub struct CreateDocumentHandler<DR, MR, RR> {
    document_repo: Arc<DR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
}

impl<DR, MR, RR> CreateDocumentHandler<DR, MR, RR>
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
        // 1. Check membership and get role
        let member = self
            .member_repo
            .find_by_workspace_and_user(command.workspace_id, command.user_id)
            .await
            .map_err(CreateDocumentError::MemberRepository)?
            .ok_or(CreateDocumentError::NotMember)?;

        // 2. Get role and check Write permission
        let role = self
            .role_repo
            .find_by_id(member.role_id)
            .await
            .map_err(CreateDocumentError::RoleRepository)?
            .ok_or(CreateDocumentError::NotMember)?;

        if !can_perform(role.base_role, WorkspacePermission::Write) {
            return Err(CreateDocumentError::PermissionDenied);
        }

        // 3. Validate encrypted title fields (must have both or neither)
        match (&command.encrypted_title, &command.encrypted_title_nonce) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(CreateDocumentError::InvalidEncryptedTitleFields);
            }
            _ => {}
        }

        // 4. Validate parent if provided
        if let Some(parent_id) = command.parent_id {
            let parent = self
                .document_repo
                .find_by_id(parent_id)
                .await
                .map_err(CreateDocumentError::DocumentRepository)?
                .ok_or(CreateDocumentError::ParentNotFound)?;

            if !parent.is_folder() {
                return Err(CreateDocumentError::ParentNotFolder);
            }

            // Check if parent is archived (cannot create documents in archived folders)
            if parent.is_archived() {
                return Err(CreateDocumentError::ParentArchived);
            }

            // Verify parent is in same workspace
            if parent.workspace_id != command.workspace_id {
                return Err(CreateDocumentError::ParentNotFound);
            }
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

        Ok(CreateDocumentResult { document })
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

/// Generate a URL-safe slug from a title
fn generate_slug(title: &str) -> String {
    let slug: String = title
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    if slug.is_empty() {
        "untitled".to_string()
    } else if slug.len() > 100 {
        slug[..100].to_string()
    } else {
        slug
    }
}
