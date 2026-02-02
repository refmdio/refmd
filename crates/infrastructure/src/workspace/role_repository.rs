//! PostgreSQL workspace role repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::workspace::{
    BaseRole, Permission, RoleId, WorkspaceId, WorkspaceRole, WorkspaceRolePermission,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

/// PostgreSQL workspace role repository
#[derive(Clone)]
pub struct PgWorkspaceRoleRepository {
    pool: PgPool,
}

impl PgWorkspaceRoleRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgWorkspaceRoleRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("corrupted data: invalid base role: {0}")]
    InvalidBaseRole(String),
}

#[derive(sqlx::FromRow)]
struct WorkspaceRoleRow {
    id: Uuid,
    workspace_id: Uuid,
    name: String,
    base_role: String,
    is_default: bool,
    created_at: DateTime<Utc>,
}

impl WorkspaceRoleRow {
    fn try_into_role(self) -> Result<WorkspaceRole, PgWorkspaceRoleRepositoryError> {
        let base_role: BaseRole = self
            .base_role
            .parse()
            .map_err(|_| PgWorkspaceRoleRepositoryError::InvalidBaseRole(self.base_role.clone()))?;

        Ok(WorkspaceRole {
            id: RoleId::from_uuid(self.id),
            workspace_id: WorkspaceId::from_uuid(self.workspace_id),
            name: self.name,
            base_role,
            is_default: self.is_default,
            created_at: self.created_at,
        })
    }
}

#[async_trait]
impl WorkspaceRoleRepository for PgWorkspaceRoleRepository {
    type Error = PgWorkspaceRoleRepositoryError;

    async fn find_by_id(&self, id: RoleId) -> Result<Option<WorkspaceRole>, Self::Error> {
        let row = sqlx::query_as::<_, WorkspaceRoleRow>(
            r#"
            SELECT id, workspace_id, name, base_role, is_default, created_at
            FROM workspace_roles
            WHERE id = $1
            "#,
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_role()).transpose()
    }

    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceRole>, Self::Error> {
        let rows = sqlx::query_as::<_, WorkspaceRoleRow>(
            r#"
            SELECT id, workspace_id, name, base_role, is_default, created_at
            FROM workspace_roles
            WHERE workspace_id = $1
            ORDER BY created_at
            "#,
        )
        .bind(workspace_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_role()).collect()
    }

    async fn find_default_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<WorkspaceRole>, Self::Error> {
        let row = sqlx::query_as::<_, WorkspaceRoleRow>(
            r#"
            SELECT id, workspace_id, name, base_role, is_default, created_at
            FROM workspace_roles
            WHERE workspace_id = $1 AND is_default = TRUE
            "#,
        )
        .bind(workspace_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_role()).transpose()
    }

    async fn save(&self, role: &WorkspaceRole) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO workspace_roles (id, workspace_id, name, base_role, is_default, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                is_default = EXCLUDED.is_default
            "#,
        )
        .bind(role.id.as_uuid())
        .bind(role.workspace_id.as_uuid())
        .bind(&role.name)
        .bind(role.base_role.as_str())
        .bind(role.is_default)
        .bind(role.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: RoleId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM workspace_roles WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM workspace_roles WHERE workspace_id = $1")
            .bind(workspace_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

/// PostgreSQL workspace role permission repository
#[derive(Clone)]
pub struct PgWorkspaceRolePermissionRepository {
    pool: PgPool,
}

impl PgWorkspaceRolePermissionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum PgWorkspaceRolePermissionRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(sqlx::FromRow)]
struct WorkspaceRolePermissionRow {
    role_id: Uuid,
    permission: String,
    granted: bool,
}

impl From<WorkspaceRolePermissionRow> for WorkspaceRolePermission {
    fn from(row: WorkspaceRolePermissionRow) -> Self {
        Self {
            role_id: RoleId::from_uuid(row.role_id),
            permission: Permission::new(row.permission),
            granted: row.granted,
        }
    }
}

#[async_trait]
impl WorkspaceRolePermissionRepository for PgWorkspaceRolePermissionRepository {
    type Error = PgWorkspaceRolePermissionRepositoryError;

    async fn find_by_role_id(
        &self,
        role_id: RoleId,
    ) -> Result<Vec<WorkspaceRolePermission>, Self::Error> {
        let rows = sqlx::query_as::<_, WorkspaceRolePermissionRow>(
            r#"
            SELECT role_id, permission, granted
            FROM workspace_role_permissions
            WHERE role_id = $1
            "#,
        )
        .bind(role_id.as_uuid())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(WorkspaceRolePermission::from)
            .collect())
    }

    async fn find_by_role_and_permission(
        &self,
        role_id: RoleId,
        permission: &Permission,
    ) -> Result<Option<WorkspaceRolePermission>, Self::Error> {
        let row = sqlx::query_as::<_, WorkspaceRolePermissionRow>(
            r#"
            SELECT role_id, permission, granted
            FROM workspace_role_permissions
            WHERE role_id = $1 AND permission = $2
            "#,
        )
        .bind(role_id.as_uuid())
        .bind(permission.as_str())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(WorkspaceRolePermission::from))
    }

    async fn save(&self, permission: &WorkspaceRolePermission) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO workspace_role_permissions (role_id, permission, granted)
            VALUES ($1, $2, $3)
            ON CONFLICT (role_id, permission) DO UPDATE SET
                granted = EXCLUDED.granted
            "#,
        )
        .bind(permission.role_id.as_uuid())
        .bind(permission.permission.as_str())
        .bind(permission.granted)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, role_id: RoleId, permission: &Permission) -> Result<(), Self::Error> {
        sqlx::query(
            "DELETE FROM workspace_role_permissions WHERE role_id = $1 AND permission = $2",
        )
        .bind(role_id.as_uuid())
        .bind(permission.as_str())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_by_role_id(&self, role_id: RoleId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM workspace_role_permissions WHERE role_id = $1")
            .bind(role_id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
