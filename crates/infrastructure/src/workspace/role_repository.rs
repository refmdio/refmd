//! PostgreSQL workspace role repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::workspace::{BaseRole, RoleId, WorkspaceId, WorkspaceRole, WorkspaceRoleRepository};
use uuid::Uuid;

pg_repo_struct!(PgWorkspaceRoleRepository);
pg_repo_error!(PgWorkspaceRoleRepositoryError, InvalidBaseRole(String));

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
        let row = sqlx::query_as!(
            WorkspaceRoleRow,
            "SELECT id, workspace_id, name, base_role, is_default, created_at FROM workspace_roles WHERE id = $1",
            id.as_uuid()
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.try_into_role()).transpose()
    }

    async fn find_by_ids(&self, ids: &[RoleId]) -> Result<Vec<WorkspaceRole>, Self::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let uuids: Vec<Uuid> = ids.iter().map(|id| id.as_uuid()).collect();
        let rows = sqlx::query_as!(
            WorkspaceRoleRow,
            "SELECT id, workspace_id, name, base_role, is_default, created_at FROM workspace_roles WHERE id = ANY($1)",
            &uuids as _
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_role()).collect()
    }

    async fn find_by_workspace_id(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceRole>, Self::Error> {
        let rows = sqlx::query_as!(
            WorkspaceRoleRow,
            "SELECT id, workspace_id, name, base_role, is_default, created_at FROM workspace_roles WHERE workspace_id = $1 ORDER BY created_at",
            workspace_id.as_uuid()
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into_role()).collect()
    }

    async fn save(&self, role: &WorkspaceRole) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            INSERT INTO workspace_roles (id, workspace_id, name, base_role, is_default, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                is_default = EXCLUDED.is_default
            "#,
            role.id.as_uuid(),
            role.workspace_id.as_uuid(),
            &role.name,
            role.base_role.as_str(),
            role.is_default,
            role.created_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: RoleId) -> Result<(), Self::Error> {
        sqlx::query!("DELETE FROM workspace_roles WHERE id = $1", id.as_uuid())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM workspace_roles WHERE workspace_id = $1",
            workspace_id.as_uuid()
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
