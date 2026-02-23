//! Transactional rotation marking service
//!
//! Atomically sets needs_kek_rotation = true on a workspace and revokes
//! all active invitations for that workspace in a single transaction.

use application::encryption::{RotationMarkingError, RotationMarkingService};
use async_trait::async_trait;
use domain::workspace::WorkspaceId;
use sqlx::PgPool;
use std::sync::Arc;

/// PostgreSQL implementation of RotationMarkingService
#[derive(Clone)]
pub struct PgRotationMarkingService {
    pool: Arc<PgPool>,
}

impl PgRotationMarkingService {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RotationMarkingService for PgRotationMarkingService {
    async fn mark_rotation_and_revoke_invitations(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<i64, RotationMarkingError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| RotationMarkingError::Database(e.to_string()))?;

        // 1. Targeted UPDATE: only set needs_kek_rotation = true
        let result = sqlx::query!(
            r#"
            UPDATE workspaces SET needs_kek_rotation = true, updated_at = NOW() WHERE id = $1
            "#,
            workspace_id.as_uuid(),
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| RotationMarkingError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(RotationMarkingError::WorkspaceNotFound);
        }

        // 2. Revoke all active invitations for this workspace
        let count = sqlx::query_scalar!(
            r#"
            WITH revoked AS (
                UPDATE workspace_invitations
                SET revoked_at = NOW()
                WHERE workspace_id = $1
                  AND revoked_at IS NULL
                  AND expires_at > NOW()
                  AND is_used = FALSE
                RETURNING id
            )
            SELECT COUNT(*) as "count!" FROM revoked
            "#,
            workspace_id.as_uuid(),
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| RotationMarkingError::Database(e.to_string()))?;

        // 3. Commit both operations atomically
        tx.commit()
            .await
            .map_err(|e| RotationMarkingError::Database(e.to_string()))?;

        Ok(count)
    }
}
