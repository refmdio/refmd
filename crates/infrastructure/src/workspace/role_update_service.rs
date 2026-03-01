//! Transactional role update service implementation

use application::workspace::{RoleUpdateError, RoleUpdateService};
use async_trait::async_trait;
use domain::identity::UserId;
use domain::workspace::{RoleId, WorkspaceId};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PgRoleUpdateService {
    pool: PgPool,
}

impl PgRoleUpdateService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleUpdateService for PgRoleUpdateService {
    async fn update_role_atomic(
        &self,
        workspace_id: WorkspaceId,
        role_id: RoleId,
        new_name: Option<&str>,
        swap_default: bool,
        permission_overrides: Option<&[(String, bool)]>,
        operator_user_id: UserId,
        expected_operator_role_id: RoleId,
    ) -> Result<(), RoleUpdateError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| RoleUpdateError::Database(e.to_string()))?;

        let ws_id: Uuid = workspace_id.as_uuid();
        let r_id: Uuid = role_id.as_uuid();

        // 0a. Operator freshness guard: lock operator's membership row with FOR UPDATE
        //     and verify role_id. This prevents concurrent demotion from committing
        //     between this check and the role mutations later in the transaction.
        let operator_role_id = sqlx::query_scalar!(
            r#"SELECT role_id FROM workspace_members
               WHERE workspace_id = $1 AND user_id = $2
               FOR UPDATE"#,
            ws_id,
            operator_user_id.as_uuid(),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| RoleUpdateError::Database(e.to_string()))?;

        match operator_role_id {
            Some(role_id) if role_id == expected_operator_role_id.as_uuid() => {}
            _ => return Err(RoleUpdateError::OperatorDemoted),
        }

        // 0b. Lock the role row (SELECT FOR UPDATE) to prevent concurrent deletes
        //     between this check and subsequent updates within the same transaction.
        //     This also verifies the role exists and belongs to the workspace.
        let locked = sqlx::query_scalar!(
            "SELECT id FROM workspace_roles WHERE id = $1 AND workspace_id = $2 FOR UPDATE",
            r_id,
            ws_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| RoleUpdateError::Database(e.to_string()))?;

        if locked.is_none() {
            return Err(RoleUpdateError::RoleNotFound);
        }

        // 1. Permission overrides (delete + re-insert)
        if let Some(overrides) = permission_overrides {
            sqlx::query!(
                "DELETE FROM workspace_role_permissions WHERE role_id = $1",
                r_id
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| RoleUpdateError::Database(e.to_string()))?;

            for (permission, granted) in overrides {
                sqlx::query!(
                    "INSERT INTO workspace_role_permissions (role_id, permission, granted) VALUES ($1, $2, $3)",
                    r_id,
                    permission,
                    granted
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| RoleUpdateError::Database(e.to_string()))?;
            }
        }

        // 2. Default swap (old default → false, target → true)
        if swap_default {
            sqlx::query!(
                "UPDATE workspace_roles SET is_default = FALSE WHERE workspace_id = $1 AND is_default = TRUE",
                ws_id
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| RoleUpdateError::Database(e.to_string()))?;

            let result = sqlx::query!(
                "UPDATE workspace_roles SET is_default = TRUE WHERE id = $1 AND workspace_id = $2",
                r_id,
                ws_id
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| RoleUpdateError::Database(e.to_string()))?;

            if result.rows_affected() == 0 {
                // Target role was concurrently deleted; tx rollback prevents zero-default state
                return Err(RoleUpdateError::RoleNotFound);
            }
        }

        // 3. Name update (workspace_id guard for defense-in-depth)
        if let Some(name) = new_name {
            sqlx::query!(
                "UPDATE workspace_roles SET name = $1 WHERE id = $2 AND workspace_id = $3",
                name,
                r_id,
                ws_id
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| RoleUpdateError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| RoleUpdateError::Database(e.to_string()))?;

        Ok(())
    }
}
