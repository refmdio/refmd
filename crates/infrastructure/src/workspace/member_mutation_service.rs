//! Transactional member mutation with Owner continuity guarantees
//!
//! Per design doc (workspace.md § Owner continuity / concurrency safety):
//! - SELECT ... FOR UPDATE on workspace_members JOIN workspace_roles
//!   WHERE base_role = 'owner' AND workspace_id = :id
//! - Re-count owners after lock
//! - Re-verify operator's role after lock
//! - Execute mutation in same transaction

use application::workspace::{MemberMutationError, MemberMutationService};
use async_trait::async_trait;
use domain::identity::UserId;
use domain::workspace::{RoleId, WorkspaceId};
use sqlx::PgPool;
use std::sync::Arc;

/// PostgreSQL implementation of MemberMutationService
#[derive(Clone)]
pub struct PgMemberMutationService {
    pool: Arc<PgPool>,
}

impl PgMemberMutationService {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MemberMutationService for PgMemberMutationService {
    async fn remove_owner_member(
        &self,
        workspace_id: WorkspaceId,
        operator_user_id: UserId,
        target_user_id: UserId,
    ) -> Result<(), MemberMutationError> {
        remove_owner_member_atomic(
            &self.pool,
            workspace_id,
            operator_user_id,
            target_user_id,
        )
        .await
        .map_err(|e| match e {
            TxError::App(e) => e,
            TxError::Db(e) => MemberMutationError::Database(e.to_string()),
        })
    }

    async fn remove_non_owner_member(
        &self,
        workspace_id: WorkspaceId,
        target_user_id: UserId,
        expected_role_id: RoleId,
    ) -> Result<(), MemberMutationError> {
        // Conditional DELETE: includes expected_role_id to guard against TOCTOU race
        // where the target's role changed between the handler's read and this DELETE.
        // If role_id no longer matches, rows_affected() == 0 → RoleConflict.
        let rows = sqlx::query!(
            "DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2 AND role_id = $3",
            workspace_id.as_uuid(),
            target_user_id.as_uuid(),
            expected_role_id.as_uuid(),
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| MemberMutationError::Database(e.to_string()))?;

        if rows.rows_affected() == 0 {
            return Err(MemberMutationError::RoleConflict);
        }
        Ok(())
    }

    async fn demote_owner_member(
        &self,
        workspace_id: WorkspaceId,
        operator_user_id: UserId,
        target_user_id: UserId,
        new_role_id: RoleId,
    ) -> Result<(), MemberMutationError> {
        demote_owner_member_atomic(
            &self.pool,
            workspace_id,
            operator_user_id,
            target_user_id,
            new_role_id,
        )
        .await
        .map_err(|e| match e {
            TxError::App(e) => e,
            TxError::Db(e) => MemberMutationError::Database(e.to_string()),
        })
    }

    async fn change_non_owner_role(
        &self,
        workspace_id: WorkspaceId,
        target_user_id: UserId,
        expected_role_id: RoleId,
        new_role_id: RoleId,
    ) -> Result<(), MemberMutationError> {
        // Conditional UPDATE: includes expected_role_id to guard against TOCTOU race
        // where the target's role changed between the handler's read and this UPDATE.
        // If role_id no longer matches, rows_affected() == 0 → RoleConflict.
        let rows = sqlx::query!(
            "UPDATE workspace_members SET role_id = $1 WHERE workspace_id = $2 AND user_id = $3 AND role_id = $4",
            new_role_id.as_uuid(),
            workspace_id.as_uuid(),
            target_user_id.as_uuid(),
            expected_role_id.as_uuid(),
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| MemberMutationError::Database(e.to_string()))?;

        if rows.rows_affected() == 0 {
            return Err(MemberMutationError::RoleConflict);
        }
        Ok(())
    }
}

enum TxError {
    App(MemberMutationError),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for TxError {
    fn from(e: sqlx::Error) -> Self {
        TxError::Db(e)
    }
}

impl From<MemberMutationError> for TxError {
    fn from(e: MemberMutationError) -> Self {
        TxError::App(e)
    }
}

/// Owner rows returned by `lock_and_verify_owners`.
struct LockedOwners {
    /// Number of owners (after lock).
    count: i64,
    /// User IDs of all current owners (locked rows).
    user_ids: Vec<uuid::Uuid>,
}

/// Lock owner rows and re-verify operator, returning owner count and user IDs.
/// Must be called within a transaction.
async fn lock_and_verify_owners(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workspace_id: WorkspaceId,
    operator_user_id: UserId,
) -> Result<LockedOwners, TxError> {
    let ws_id = workspace_id.as_uuid();
    let op_id = operator_user_id.as_uuid();

    // SELECT ... FOR UPDATE on all owner member rows
    // This locks them so concurrent demote/remove operations serialise
    let owner_rows = sqlx::query_scalar!(
        r#"
        SELECT m.user_id as "user_id!"
        FROM workspace_members m
        JOIN workspace_roles r ON r.id = m.role_id
        WHERE m.workspace_id = $1
          AND r.base_role = 'owner'
        FOR UPDATE OF m
        "#,
        ws_id,
    )
    .fetch_all(&mut **tx)
    .await?;

    let count = owner_rows.len() as i64;

    // Re-verify operator is still an Owner after lock acquisition
    // (they might have been demoted by a concurrent operation that committed before our lock)
    if !owner_rows.iter().any(|uid| *uid == op_id) {
        return Err(MemberMutationError::OperatorDemoted.into());
    }

    Ok(LockedOwners { count, user_ids: owner_rows })
}

async fn remove_owner_member_atomic(
    pool: &PgPool,
    workspace_id: WorkspaceId,
    operator_user_id: UserId,
    target_user_id: UserId,
) -> Result<(), TxError> {
    let mut tx = pool.begin().await?;

    // 1. Lock owner rows + re-verify operator
    let owners =
        lock_and_verify_owners(&mut tx, workspace_id, operator_user_id).await?;

    // 2. Verify target is still an Owner (TOCTOU protection — their role may
    //    have changed concurrently before we acquired the lock)
    if !owners.user_ids.iter().any(|uid| *uid == target_user_id.as_uuid()) {
        return Err(MemberMutationError::RoleConflict.into());
    }

    // 3. Check last owner
    if owners.count <= 1 {
        return Err(MemberMutationError::LastOwner.into());
    }

    // 4. Delete target member.
    //    Target is confirmed to be an Owner via the locked rows above.
    let rows = sqlx::query!(
        "DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2",
        workspace_id.as_uuid(),
        target_user_id.as_uuid(),
    )
    .execute(&mut *tx)
    .await?;

    if rows.rows_affected() == 0 {
        return Err(MemberMutationError::TargetNotFound.into());
    }

    tx.commit().await?;
    Ok(())
}

async fn demote_owner_member_atomic(
    pool: &PgPool,
    workspace_id: WorkspaceId,
    operator_user_id: UserId,
    target_user_id: UserId,
    new_role_id: RoleId,
) -> Result<(), TxError> {
    let mut tx = pool.begin().await?;

    // 1. Lock owner rows + re-verify operator
    let owners =
        lock_and_verify_owners(&mut tx, workspace_id, operator_user_id).await?;

    // 2. Verify target is still an Owner (TOCTOU protection — their role may
    //    have changed concurrently before we acquired the lock)
    if !owners.user_ids.iter().any(|uid| *uid == target_user_id.as_uuid()) {
        return Err(MemberMutationError::RoleConflict.into());
    }

    // 3. Check last owner
    if owners.count <= 1 {
        return Err(MemberMutationError::LastOwner.into());
    }

    // 4. Verify the new role exists and belongs to this workspace
    let role_exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM workspace_roles WHERE id = $1 AND workspace_id = $2) as \"exists!\"",
        new_role_id.as_uuid(),
        workspace_id.as_uuid(),
    )
    .fetch_one(&mut *tx)
    .await?;

    if !role_exists {
        return Err(MemberMutationError::TargetRoleNotFound.into());
    }

    // 5. Update target member's role.
    //    The target role (new_role_id) was verified to exist in step 4 within this
    //    same transaction. If it gets deleted by a concurrent operation, the FK
    //    constraint on workspace_members.role_id will reject the UPDATE, surfacing
    //    as a Database error — which is the correct behaviour (caller can retry).
    let rows = sqlx::query!(
        "UPDATE workspace_members SET role_id = $1 WHERE workspace_id = $2 AND user_id = $3",
        new_role_id.as_uuid(),
        workspace_id.as_uuid(),
        target_user_id.as_uuid(),
    )
    .execute(&mut *tx)
    .await?;

    if rows.rows_affected() == 0 {
        return Err(MemberMutationError::TargetNotFound.into());
    }

    tx.commit().await?;
    Ok(())
}
