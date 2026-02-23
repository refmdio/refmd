//! PostgreSQL workspace role repository implementation

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::workspace::{
    BaseRole, RoleId, WorkspaceId, WorkspaceRole, WorkspaceRoleRepository,
    WorkspaceRoleRepositoryErrorClassifier,
};
use uuid::Uuid;

pg_repo_struct!(PgWorkspaceRoleRepository);
pg_repo_error!(PgWorkspaceRoleRepositoryError, InvalidBaseRole(String), RoleNotFound(String), RoleInUse(String), RoleBecameDefault(String));

impl WorkspaceRoleRepositoryErrorClassifier for PgWorkspaceRoleRepositoryError {
    fn is_role_in_use(&self) -> bool {
        matches!(self, Self::RoleInUse(_))
    }
    fn is_role_became_default(&self) -> bool {
        matches!(self, Self::RoleBecameDefault(_))
    }
    fn is_role_not_found(&self) -> bool {
        matches!(self, Self::RoleNotFound(_))
    }
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

    async fn update(&self, role: &WorkspaceRole) -> Result<bool, Self::Error> {
        // Only update `name`. The `is_default` flag is managed exclusively
        // through `swap_default()` to avoid overwriting concurrent changes.
        // workspace_id guard for defense-in-depth (role IDs are globally unique
        // but scoping prevents accidental cross-workspace mutation).
        let result = sqlx::query!(
            r#"
            UPDATE workspace_roles SET name = $2 WHERE id = $1 AND workspace_id = $3
            "#,
            role.id.as_uuid(),
            &role.name,
            role.workspace_id.as_uuid(),
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete(&self, id: RoleId, workspace_id: WorkspaceId) -> Result<(), Self::Error> {
        // Conditional delete: only delete if not default AND belongs to workspace
        // (workspace_id guard for defense-in-depth; TOCTOU protection against
        // concurrent swap_default making this role the default between the handler's
        // is_default check and this DELETE).
        match sqlx::query!(
            "DELETE FROM workspace_roles WHERE id = $1 AND workspace_id = $2 AND is_default = false",
            id.as_uuid(),
            workspace_id.as_uuid()
        )
            .execute(&self.pool)
            .await
        {
            Ok(result) => {
                if result.rows_affected() == 0 {
                    // 0 rows: either role doesn't exist, or it became default concurrently.
                    // Check which case so the app layer can return the right HTTP status.
                    let exists = sqlx::query_scalar!(
                        r#"SELECT EXISTS(SELECT 1 FROM workspace_roles WHERE id = $1 AND workspace_id = $2) as "exists!""#,
                        id.as_uuid(),
                        workspace_id.as_uuid()
                    )
                    .fetch_one(&self.pool)
                    .await
                    .map_err(PgWorkspaceRoleRepositoryError::from)?;

                    if exists {
                        // Role exists but is_default=true — became default concurrently
                        return Err(PgWorkspaceRoleRepositoryError::RoleBecameDefault(
                            format!("role {} is now the default role and cannot be deleted", id),
                        ));
                    }
                    return Err(PgWorkspaceRoleRepositoryError::RoleNotFound(
                        format!("role {} not found", id),
                    ));
                }
                Ok(())
            }
            Err(sqlx::Error::Database(ref db_err)) if db_err.code().as_deref() == Some("23503") => {
                // FK violation — members are still assigned to this role (TOCTOU race
                // between the application-layer "no members assigned" check and this DELETE).
                Err(PgWorkspaceRoleRepositoryError::RoleInUse(
                    format!("role {} is still referenced by members", id),
                ))
            }
            Err(e) => Err(e.into()),
        }
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

    async fn swap_default(
        &self,
        workspace_id: WorkspaceId,
        new_default_role_id: RoleId,
        new_name: Option<&str>,
    ) -> Result<(), Self::Error> {
        // Atomically: old default → false, new default → true (+ optional name update)
        let mut tx = self.pool.begin().await?;

        sqlx::query!(
            "UPDATE workspace_roles SET is_default = false WHERE workspace_id = $1 AND is_default = true",
            workspace_id.as_uuid()
        )
        .execute(&mut *tx)
        .await?;

        let result = sqlx::query!(
            "UPDATE workspace_roles SET is_default = true WHERE id = $1 AND workspace_id = $2",
            new_default_role_id.as_uuid(),
            workspace_id.as_uuid()
        )
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            // Role was deleted between load and swap — rollback (tx drops)
            return Err(PgWorkspaceRoleRepositoryError::RoleNotFound(
                format!("swap_default: target role {} not found in workspace", new_default_role_id),
            ));
        }

        // Update name in the same transaction if provided (workspace_id guard)
        if let Some(name) = new_name {
            sqlx::query!(
                "UPDATE workspace_roles SET name = $1 WHERE id = $2 AND workspace_id = $3",
                name,
                new_default_role_id.as_uuid(),
                workspace_id.as_uuid()
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn save_and_set_default(&self, role: &WorkspaceRole) -> Result<(), Self::Error> {
        let mut tx = self.pool.begin().await?;

        // 1. Insert the new role (is_default=false to avoid partial unique index violation)
        sqlx::query!(
            r#"
            INSERT INTO workspace_roles (id, workspace_id, name, base_role, is_default, created_at)
            VALUES ($1, $2, $3, $4, false, $5)
            "#,
            role.id.as_uuid(),
            role.workspace_id.as_uuid(),
            &role.name,
            role.base_role.as_str(),
            role.created_at
        )
        .execute(&mut *tx)
        .await?;

        // 2. Unset old default
        sqlx::query!(
            "UPDATE workspace_roles SET is_default = false WHERE workspace_id = $1 AND is_default = true",
            role.workspace_id.as_uuid()
        )
        .execute(&mut *tx)
        .await?;

        // 3. Set new role as default (workspace_id guard for defense-in-depth)
        sqlx::query!(
            "UPDATE workspace_roles SET is_default = true WHERE id = $1 AND workspace_id = $2",
            role.id.as_uuid(),
            role.workspace_id.as_uuid()
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }
}
