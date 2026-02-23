//! Update workspace command
//!
//! Updates workspace name/slug/description/icon. Requires workspace:update permission.

use crate::dto::WorkspaceDto;
use crate::util::slug::generate_workspace_slug;
use crate::util::workspace_access::{WorkspaceAccessError, check_workspace_permission};
use domain::identity::UserId;
use domain::workspace::{
    Slug, WorkspaceId, WorkspaceMemberRepository, WorkspaceRepository,
    WorkspaceRepositoryErrorClassifier, WorkspaceRolePermissionRepository,
    WorkspaceRoleRepository, permission,
};
use std::sync::Arc;
use thiserror::Error;

/// Update workspace command
#[derive(Debug)]
pub struct UpdateWorkspaceCommand {
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub name: Option<String>,
    pub slug: Option<String>,
    pub description: Option<Option<String>>,
    pub icon: Option<Option<String>>,
}

/// Update workspace result
#[derive(Debug)]
pub struct UpdateWorkspaceResult {
    pub workspace: WorkspaceDto,
}

/// Update workspace error
#[derive(Debug, Error)]
pub enum UpdateWorkspaceError<
    WR: std::error::Error,
    MR: std::error::Error,
    RR: std::error::Error,
    RPR: std::error::Error,
> {
    #[error("workspace not found")]
    WorkspaceNotFound,

    #[error(transparent)]
    WorkspaceAccess(WorkspaceAccessError<MR, RR, RPR>),

    #[error("workspace name is empty")]
    EmptyName,

    #[error("workspace name is too long (max 100 characters)")]
    NameTooLong,

    #[error("invalid slug: {0}")]
    InvalidSlug(String),

    #[error("slug is already taken")]
    SlugTaken,

    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),
}

crate::types::impl_app_error!(
    [WR: std::error::Error, MR: std::error::Error, RR: std::error::Error, RPR: std::error::Error]
    UpdateWorkspaceError<WR, MR, RR, RPR>,
    not_found: [
        UpdateWorkspaceError::WorkspaceNotFound,
        UpdateWorkspaceError::WorkspaceAccess(WorkspaceAccessError::NotMember),
    ],
    access_denied: [
        UpdateWorkspaceError::WorkspaceAccess(WorkspaceAccessError::PermissionDenied),
    ],
    invalid_input: [
        UpdateWorkspaceError::EmptyName,
        UpdateWorkspaceError::NameTooLong,
        UpdateWorkspaceError::InvalidSlug(_),
    ],
    conflict: [
        UpdateWorkspaceError::SlugTaken,
    ],
);

/// Update workspace handler
pub struct UpdateWorkspaceHandler<WR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> {
    workspace_repo: Arc<WR>,
    member_repo: Arc<MR>,
    role_repo: Arc<RR>,
    role_perm_repo: Arc<RPR>,
}

impl<WR: ?Sized, MR: ?Sized, RR: ?Sized, RPR: ?Sized> UpdateWorkspaceHandler<WR, MR, RR, RPR>
where
    WR: WorkspaceRepository,
    MR: WorkspaceMemberRepository,
    RR: WorkspaceRoleRepository,
    RPR: WorkspaceRolePermissionRepository,
{
    pub fn new(
        workspace_repo: Arc<WR>,
        member_repo: Arc<MR>,
        role_repo: Arc<RR>,
        role_perm_repo: Arc<RPR>,
    ) -> Self {
        Self {
            workspace_repo,
            member_repo,
            role_repo,
            role_perm_repo,
        }
    }

    pub async fn handle(
        &self,
        command: UpdateWorkspaceCommand,
    ) -> Result<UpdateWorkspaceResult, UpdateWorkspaceError<WR::Error, MR::Error, RR::Error, RPR::Error>> {
        // 1. Permission check
        check_workspace_permission(
            &self.member_repo,
            &self.role_repo,
            &self.role_perm_repo,
            command.workspace_id,
            command.user_id,
            permission::WORKSPACE_UPDATE,
        )
        .await
        .map_err(UpdateWorkspaceError::WorkspaceAccess)?;

        // 2. Load workspace
        let mut workspace = self
            .workspace_repo
            .find_by_id(command.workspace_id)
            .await
            .map_err(UpdateWorkspaceError::WorkspaceRepository)?
            .ok_or(UpdateWorkspaceError::WorkspaceNotFound)?;

        // 3. Validate and trim name if provided
        let trimmed_name: Option<String> = if let Some(ref name) = command.name {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(UpdateWorkspaceError::EmptyName);
            }
            if trimmed.len() > 100 {
                return Err(UpdateWorkspaceError::NameTooLong);
            }
            Some(trimmed.to_string())
        } else {
            None
        };

        // 4. Validate and resolve slug if provided
        let resolved_slug: Option<Slug> = if let Some(ref slug_input) = command.slug {
            let slug = generate_workspace_slug(slug_input)
                .map_err(|e| UpdateWorkspaceError::InvalidSlug(e.to_string()))?;

            // Only check uniqueness if the slug is actually changing
            if slug != workspace.slug {
                let exists = self
                    .workspace_repo
                    .slug_exists(&slug)
                    .await
                    .map_err(UpdateWorkspaceError::WorkspaceRepository)?;
                if exists {
                    return Err(UpdateWorkspaceError::SlugTaken);
                }
            }
            Some(slug)
        } else {
            None
        };

        // 5. Apply updates
        workspace.update(trimmed_name, resolved_slug, command.description, command.icon);

        // 6. Update (not UPSERT — prevents resurrecting a deleted workspace)
        let updated = self
            .workspace_repo
            .update(&workspace)
            .await
            .map_err(|e| {
                if e.is_slug_conflict() {
                    UpdateWorkspaceError::SlugTaken
                } else {
                    UpdateWorkspaceError::WorkspaceRepository(e)
                }
            })?;
        if !updated {
            return Err(UpdateWorkspaceError::WorkspaceNotFound);
        }

        Ok(UpdateWorkspaceResult {
            workspace: workspace.into(),
        })
    }
}
