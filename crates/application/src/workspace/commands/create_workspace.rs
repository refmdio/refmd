//! Create workspace command
//!
//! Creates a new workspace with default roles.

use std::sync::Arc;
use domain::identity::UserId;
use domain::workspace::{
    Slug, SlugError, Workspace, WorkspaceMember, WorkspaceMemberRepository, WorkspaceRepository,
    WorkspaceRole, WorkspaceRoleRepository,
};
use thiserror::Error;

/// Create workspace command
#[derive(Debug)]
pub struct CreateWorkspaceCommand {
    /// User ID who will own the workspace
    pub owner_id: UserId,
    /// Workspace name
    pub name: String,
    /// Optional slug (will be generated from name if not provided)
    pub slug: Option<String>,
}

/// Create workspace result
#[derive(Debug)]
pub struct CreateWorkspaceResult {
    pub workspace: Workspace,
    pub owner_role: WorkspaceRole,
    pub member: WorkspaceMember,
}

/// Create workspace error
#[derive(Debug, Error)]
pub enum CreateWorkspaceError<WR: std::error::Error, WMR: std::error::Error, WRR: std::error::Error> {
    #[error("invalid slug: {0}")]
    InvalidSlug(#[from] SlugError),

    #[error("slug already exists")]
    SlugExists,

    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),

    #[error("workspace member repository error: {0}")]
    WorkspaceMemberRepository(WMR),

    #[error("workspace role repository error: {0}")]
    WorkspaceRoleRepository(WRR),
}

/// Create workspace handler
pub struct CreateWorkspaceHandler<WR, WMR, WRR> {
    workspace_repo: Arc<WR>,
    member_repo: Arc<WMR>,
    role_repo: Arc<WRR>,
}

impl<WR, WMR, WRR> CreateWorkspaceHandler<WR, WMR, WRR>
where
    WR: WorkspaceRepository,
    WMR: WorkspaceMemberRepository,
    WRR: WorkspaceRoleRepository,
{
    pub fn new(
        workspace_repo: Arc<WR>,
        member_repo: Arc<WMR>,
        role_repo: Arc<WRR>,
    ) -> Self {
        Self {
            workspace_repo,
            member_repo,
            role_repo,
        }
    }

    pub async fn handle(
        &self,
        command: CreateWorkspaceCommand,
    ) -> Result<CreateWorkspaceResult, CreateWorkspaceError<WR::Error, WMR::Error, WRR::Error>>
    {
        // Generate or validate slug
        let base_slug = match command.slug {
            Some(s) => Slug::new(s)?,
            None => generate_slug(&command.name)?,
        };

        // Ensure slug is unique
        let final_slug = self.ensure_unique_slug(base_slug).await?;

        // Create workspace
        let workspace = Workspace::new(command.name, final_slug, command.owner_id);

        // Save workspace
        self.workspace_repo
            .save(&workspace)
            .await
            .map_err(CreateWorkspaceError::WorkspaceRepository)?;

        // Create owner role
        let owner_role = WorkspaceRole::owner(workspace.id);
        self.role_repo
            .save(&owner_role)
            .await
            .map_err(CreateWorkspaceError::WorkspaceRoleRepository)?;

        // Create default roles (editor, viewer)
        let editor_role = WorkspaceRole::editor(workspace.id);
        let viewer_role = WorkspaceRole::viewer(workspace.id);
        self.role_repo
            .save(&editor_role)
            .await
            .map_err(CreateWorkspaceError::WorkspaceRoleRepository)?;
        self.role_repo
            .save(&viewer_role)
            .await
            .map_err(CreateWorkspaceError::WorkspaceRoleRepository)?;

        // Add owner as member (not default workspace - that's only for first workspace)
        let member = WorkspaceMember::new(workspace.id, command.owner_id, owner_role.id, false);
        self.member_repo
            .save(&member)
            .await
            .map_err(CreateWorkspaceError::WorkspaceMemberRepository)?;

        Ok(CreateWorkspaceResult {
            workspace,
            owner_role,
            member,
        })
    }

    async fn ensure_unique_slug(
        &self,
        base_slug: Slug,
    ) -> Result<Slug, CreateWorkspaceError<WR::Error, WMR::Error, WRR::Error>> {
        let exists = self
            .workspace_repo
            .slug_exists(&base_slug)
            .await
            .map_err(CreateWorkspaceError::WorkspaceRepository)?;

        if !exists {
            return Ok(base_slug);
        }

        // Try with random suffixes
        for _ in 0..10 {
            let suffix = generate_random_suffix();
            let new_slug_str = format!("{}-{}", base_slug.as_str(), suffix);
            if let Ok(new_slug) = Slug::new(new_slug_str) {
                let exists = self
                    .workspace_repo
                    .slug_exists(&new_slug)
                    .await
                    .map_err(CreateWorkspaceError::WorkspaceRepository)?;

                if !exists {
                    return Ok(new_slug);
                }
            }
        }

        Err(CreateWorkspaceError::SlugExists)
    }
}

/// Generate a URL-safe slug from a name
fn generate_slug(name: &str) -> Result<Slug, SlugError> {
    let slug_str: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    if slug_str.is_empty() {
        return Slug::new("workspace");
    }

    Slug::new(slug_str)
}

/// Generate a random 4-character suffix
fn generate_random_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:04x}", nanos % 0xFFFF)
}
