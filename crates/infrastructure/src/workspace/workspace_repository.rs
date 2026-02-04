//! PostgreSQL workspace repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::identity::UserId;
use domain::workspace::{Slug, Workspace, WorkspaceId, WorkspaceRepository};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL workspace repository
#[derive(Clone)]
pub struct PgWorkspaceRepository {
    pool: PgPool,
}

impl PgWorkspaceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgWorkspaceRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("corrupted data: invalid slug: {0}")]
    InvalidSlug(String),
}

#[derive(sqlx::FromRow)]
struct WorkspaceRow {
    id: Uuid,
    name: String,
    slug: String,
    description: Option<String>,
    icon: Option<String>,
    owner_id: Uuid,
    min_kek_version: i32,
    needs_kek_rotation: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl WorkspaceRow {
    fn try_into_workspace(self) -> Result<Workspace, PgWorkspaceRepositoryError> {
        let slug = Slug::new(&self.slug)
            .map_err(|_| PgWorkspaceRepositoryError::InvalidSlug(self.slug.clone()))?;

        Ok(Workspace {
            id: WorkspaceId::from_uuid(self.id),
            name: self.name,
            slug,
            description: self.description,
            icon: self.icon,
            owner_id: UserId::from_uuid(self.owner_id),
            min_kek_version: self.min_kek_version,
            needs_kek_rotation: self.needs_kek_rotation,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[async_trait]
impl WorkspaceRepository for PgWorkspaceRepository {
    type Error = PgWorkspaceRepositoryError;

    async fn find_by_id(&self, id: WorkspaceId) -> Result<Option<Workspace>, Self::Error> {
        let row = sqlx::query_as::<_, WorkspaceRow>(
            r#"
            SELECT id, name, slug, description, icon, owner_id, min_kek_version, needs_kek_rotation, created_at, updated_at
            FROM workspaces
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_workspace()).transpose()
    }

    async fn find_by_slug(&self, slug: &Slug) -> Result<Option<Workspace>, Self::Error> {
        let row = sqlx::query_as::<_, WorkspaceRow>(
            r#"
            SELECT id, name, slug, description, icon, owner_id, min_kek_version, needs_kek_rotation, created_at, updated_at
            FROM workspaces
            WHERE slug = $1
            "#,
        )
        .bind(slug.as_str())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_workspace()).transpose()
    }

    async fn find_by_owner_id(&self, owner_id: UserId) -> Result<Vec<Workspace>, Self::Error> {
        let rows = sqlx::query_as::<_, WorkspaceRow>(
            r#"
            SELECT id, name, slug, description, icon, owner_id, min_kek_version, needs_kek_rotation, created_at, updated_at
            FROM workspaces
            WHERE owner_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(owner_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_workspace()).collect()
    }

    async fn slug_exists(&self, slug: &Slug) -> Result<bool, Self::Error> {
        let result = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(SELECT 1 FROM workspaces WHERE slug = $1)
            "#,
        )
        .bind(slug.as_str())
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn save(&self, workspace: &Workspace) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO workspaces (id, name, slug, description, icon, owner_id, min_kek_version, needs_kek_rotation, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                icon = EXCLUDED.icon,
                min_kek_version = EXCLUDED.min_kek_version,
                needs_kek_rotation = EXCLUDED.needs_kek_rotation,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(workspace.id.as_uuid())
        .bind(&workspace.name)
        .bind(workspace.slug.as_str())
        .bind(&workspace.description)
        .bind(&workspace.icon)
        .bind(workspace.owner_id.as_uuid())
        .bind(workspace.min_kek_version)
        .bind(workspace.needs_kek_rotation)
        .bind(workspace.created_at)
        .bind(workspace.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: WorkspaceId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM workspaces WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
