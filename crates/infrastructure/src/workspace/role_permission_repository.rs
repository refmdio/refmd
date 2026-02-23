//! PostgreSQL workspace role permission repository implementation

use async_trait::async_trait;
use domain::workspace::{RoleId, WorkspaceRolePermission, WorkspaceRolePermissionRepository};
use uuid::Uuid;

pg_repo_struct!(PgWorkspaceRolePermissionRepository);
pg_repo_error!(PgWorkspaceRolePermissionRepositoryError);

#[derive(sqlx::FromRow)]
struct RolePermissionRow {
    role_id: Uuid,
    permission: String,
    granted: bool,
}

impl RolePermissionRow {
    fn into_domain(self) -> WorkspaceRolePermission {
        WorkspaceRolePermission {
            role_id: RoleId::from_uuid(self.role_id),
            permission: self.permission,
            granted: self.granted,
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
        let rows = sqlx::query_as!(
            RolePermissionRow,
            "SELECT role_id, permission, granted FROM workspace_role_permissions WHERE role_id = $1",
            role_id.as_uuid()
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_domain()).collect())
    }

    async fn find_by_role_ids(
        &self,
        role_ids: &[RoleId],
    ) -> Result<Vec<WorkspaceRolePermission>, Self::Error> {
        if role_ids.is_empty() {
            return Ok(Vec::new());
        }
        let uuids: Vec<Uuid> = role_ids.iter().map(|id| id.as_uuid()).collect();
        let rows = sqlx::query_as!(
            RolePermissionRow,
            "SELECT role_id, permission, granted FROM workspace_role_permissions WHERE role_id = ANY($1)",
            &uuids as _
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_domain()).collect())
    }

    async fn save_batch(
        &self,
        role_id: RoleId,
        perms: &[(String, bool)],
    ) -> Result<(), Self::Error> {
        // Delete existing and re-insert
        let mut tx = self.pool.begin().await?;

        sqlx::query!(
            "DELETE FROM workspace_role_permissions WHERE role_id = $1",
            role_id.as_uuid()
        )
        .execute(&mut *tx)
        .await?;

        for (permission, granted) in perms {
            sqlx::query!(
                r#"
                INSERT INTO workspace_role_permissions (role_id, permission, granted)
                VALUES ($1, $2, $3)
                "#,
                role_id.as_uuid(),
                permission,
                granted
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn delete_by_role_id(&self, role_id: RoleId) -> Result<(), Self::Error> {
        sqlx::query!(
            "DELETE FROM workspace_role_permissions WHERE role_id = $1",
            role_id.as_uuid()
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
