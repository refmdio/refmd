//! Transactional KEK rotation completion
//!
//! Follows the design doc concurrency requirements:
//! 1. FOR UPDATE lock on workspace row (serialise with invitation creation)
//! 2. Validate needs_kek_rotation = true
//! 3. Validate new_min_kek_version > current min_kek_version
//! 4. Verify all active devices of current members have the new KEK
//! 5. UPDATE workspace min_kek_version and clear rotation flag

use application::encryption::{KekRotationCompletionError, KekRotationCompletionService};
use async_trait::async_trait;
use domain::workspace::WorkspaceId;
use sqlx::PgPool;
use std::sync::Arc;

/// PostgreSQL implementation of KekRotationCompletionService
#[derive(Clone)]
pub struct PgKekRotationCompletionService {
    pool: Arc<PgPool>,
}

impl PgKekRotationCompletionService {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl KekRotationCompletionService for PgKekRotationCompletionService {
    async fn complete_atomic(
        &self,
        workspace_id: WorkspaceId,
        user_id: domain::identity::UserId,
        new_min_kek_version: i32,
    ) -> Result<(), KekRotationCompletionError> {
        complete_rotation_atomic(&self.pool, workspace_id, user_id, new_min_kek_version)
            .await
            .map_err(|e| match e {
                CompleteError::App(e) => e,
                CompleteError::Db(e) => KekRotationCompletionError::Database(e.to_string()),
            })
    }
}

enum CompleteError {
    App(KekRotationCompletionError),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for CompleteError {
    fn from(e: sqlx::Error) -> Self {
        CompleteError::Db(e)
    }
}

impl From<KekRotationCompletionError> for CompleteError {
    fn from(e: KekRotationCompletionError) -> Self {
        CompleteError::App(e)
    }
}

async fn complete_rotation_atomic(
    pool: &PgPool,
    workspace_id: WorkspaceId,
    user_id: domain::identity::UserId,
    new_min_kek_version: i32,
) -> Result<(), CompleteError> {
    let ws_id = workspace_id.as_uuid();
    let uid = user_id.as_uuid();

    let mut tx = pool.begin().await?;

    // 1. FOR UPDATE lock on workspace row — serialise with invitation creation
    //    and concurrent rotation attempts
    let ws = sqlx::query!(
        r#"SELECT needs_kek_rotation, min_kek_version
           FROM workspaces WHERE id = $1 FOR UPDATE"#,
        ws_id,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(KekRotationCompletionError::WorkspaceNotFound)?;

    // 2. Check needs_kek_rotation = true
    if !ws.needs_kek_rotation {
        return Err(KekRotationCompletionError::NotNeedsRotation.into());
    }

    // 3. Validate new version > current
    if new_min_kek_version <= ws.min_kek_version {
        return Err(KekRotationCompletionError::InvalidVersion {
            current: ws.min_kek_version,
            new: new_min_kek_version,
        }
        .into());
    }

    // 4. Check: any active key for the requesting user on non-revoked devices
    //    with old version (< new_min_kek_version)?
    //    Scoped to the requesting user because E2EE key distribution is
    //    user-scoped — each user can only encrypt KEK for their own devices.
    //    Other members get the new KEK via UMK backup restore.
    let has_old_key = sqlx::query_scalar!(
        r#"SELECT EXISTS(
            SELECT 1 FROM workspace_encrypted_keys wek
            JOIN devices d
                ON wek.device_id = d.id AND d.user_id = wek.user_id AND d.revoked_at IS NULL
            WHERE wek.workspace_id = $1
              AND wek.user_id = $3
              AND wek.is_active = true
              AND wek.key_version < $2
        ) as "has_old_key!""#,
        ws_id,
        new_min_kek_version,
        uid,
    )
    .fetch_one(&mut *tx)
    .await?;

    if has_old_key {
        return Err(KekRotationCompletionError::DistributionIncomplete.into());
    }

    // 5. Check: any active device of the requesting user WITHOUT a key >= new version?
    let missing_key = sqlx::query_scalar!(
        r#"SELECT EXISTS(
            SELECT 1 FROM devices d
            WHERE d.user_id = $3
              AND d.revoked_at IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM workspace_encrypted_keys wek
                  WHERE wek.workspace_id = $1
                    AND wek.device_id = d.id
                    AND wek.is_active = true
                    AND wek.key_version >= $2
              )
        ) as "missing_key!""#,
        ws_id,
        new_min_kek_version,
        uid,
    )
    .fetch_one(&mut *tx)
    .await?;

    if missing_key {
        return Err(KekRotationCompletionError::DistributionIncomplete.into());
    }

    // 6. UPDATE workspace: set new min_kek_version, clear rotation flag
    sqlx::query!(
        r#"UPDATE workspaces
           SET min_kek_version = $1, needs_kek_rotation = false
           WHERE id = $2"#,
        new_min_kek_version,
        ws_id,
    )
    .execute(&mut *tx)
    .await?;

    // 7. COMMIT
    tx.commit().await?;

    Ok(())
}
