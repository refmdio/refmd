//! Transactional invitation acceptance
//!
//! Follows the design doc transaction flow exactly:
//! 1. Lookup invitation by token_hash (regardless of revoked_at)
//! 2. Existing member check → simplified validation (idempotent path)
//! 3. New member → atomic CTE with all validations in WHERE clause
//! 4. Result determination with fallback on CTE failure

use application::workspace::{
    InvitationAcceptanceError, InvitationAcceptanceResult, InvitationAcceptanceService,
};
use async_trait::async_trait;
use chrono::Utc;
use domain::identity::UserId;
use domain::workspace::{InvitationId, WorkspaceId};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

/// PostgreSQL implementation of InvitationAcceptanceService
#[derive(Clone)]
pub struct PgInvitationAcceptanceService {
    pool: Arc<PgPool>,
}

impl PgInvitationAcceptanceService {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InvitationAcceptanceService for PgInvitationAcceptanceService {
    async fn accept_atomic(
        &self,
        token_hash: &str,
        user_id: UserId,
        user_email: &str,
    ) -> Result<InvitationAcceptanceResult, InvitationAcceptanceError> {
        accept_invitation_atomic(&self.pool, token_hash, user_id, user_email)
            .await
            .map_err(|e| match e {
                AcceptError::App(e) => e,
                AcceptError::Db(e) => InvitationAcceptanceError::Database(e.to_string()),
            })
    }
}

enum AcceptError {
    App(InvitationAcceptanceError),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for AcceptError {
    fn from(e: sqlx::Error) -> Self {
        AcceptError::Db(e)
    }
}

impl From<InvitationAcceptanceError> for AcceptError {
    fn from(e: InvitationAcceptanceError) -> Self {
        AcceptError::App(e)
    }
}

async fn accept_invitation_atomic(
    pool: &PgPool,
    token_hash: &str,
    user_id: UserId,
    user_email: &str,
) -> Result<InvitationAcceptanceResult, AcceptError> {
    // ── Step 1: Lookup invitation by token_hash ──
    // Fetches only fields needed for the response + the CTE.
    // Searches regardless of revoked_at (per design doc).
    let inv = sqlx::query!(
        r#"
        SELECT i.id, i.workspace_id,
               i.encrypted_kek as "encrypted_kek!",
               i.kek_nonce as "kek_nonce!",
               i.kek_version as "kek_version!",
               i.invited_email,
               i.revoked_at, i.expires_at, i.is_used,
               w.name AS workspace_name,
               r.name AS "role_name?"
        FROM workspace_invitations i
        JOIN workspaces w ON w.id = i.workspace_id
        LEFT JOIN workspace_roles r ON r.id = i.role_id
        WHERE i.token_hash = $1
        "#,
        token_hash,
    )
    .fetch_optional(pool)
    .await?
    .ok_or(InvitationAcceptanceError::NotFound)?;

    let encrypted_kek = inv.encrypted_kek;
    let kek_nonce = inv.kek_nonce;
    let kek_version = inv.kek_version;

    let build_result = |inv_id: Uuid, ws_id: Uuid, ws_name: String, r_name: Option<String>| {
        InvitationAcceptanceResult {
            invitation_id: InvitationId::from_uuid(inv_id),
            workspace_id: WorkspaceId::from_uuid(ws_id),
            workspace_name: ws_name,
            role_name: r_name,
            encrypted_kek: encrypted_kek.clone(),
            kek_nonce: kek_nonce.clone(),
            kek_version,
        }
    };

    // ── Step 2: Existing member check (idempotent path) ──
    let is_member = sqlx::query_scalar!(
        "SELECT 1 AS v FROM workspace_members WHERE workspace_id = $1 AND user_id = $2",
        inv.workspace_id,
        user_id.as_uuid(),
    )
    .fetch_optional(pool)
    .await?
    .is_some();

    if is_member {
        // Existing member idempotent path — defense in depth:
        // Check revoked_at, expires_at, invited_email in addition to needs_kek_rotation
        // and kek_version. Although the member can access KEK through normal device
        // distribution, we honour explicit revocation intent and minimize KEK distribution
        // paths as a security-first policy.
        if inv.revoked_at.is_some() {
            return Err(InvitationAcceptanceError::Revoked.into());
        }
        if inv.expires_at <= Utc::now() {
            return Err(InvitationAcceptanceError::Expired.into());
        }
        if inv.invited_email != user_email {
            return Err(InvitationAcceptanceError::EmailMismatch.into());
        }

        // FOR SHARE serialises with KEK-rotation UPDATE.
        let ws = sqlx::query!(
            "SELECT needs_kek_rotation, min_kek_version FROM workspaces WHERE id = $1 FOR SHARE",
            inv.workspace_id,
        )
        .fetch_optional(pool)
        .await?
        .ok_or(InvitationAcceptanceError::NotFound)?;

        if ws.needs_kek_rotation {
            return Err(InvitationAcceptanceError::KekRotationInProgress.into());
        }
        if kek_version < ws.min_kek_version {
            return Err(InvitationAcceptanceError::StaleKekVersion.into());
        }

        return Ok(build_result(
            inv.id,
            inv.workspace_id,
            inv.workspace_name,
            inv.role_name,
        ));
    }

    // ── Step 3: New member — atomic CTE (design doc SQL) ──
    let mut tx = pool.begin().await?;

    let cte_result = sqlx::query!(
        r#"
        WITH workspace_guard AS (
            SELECT w.id, w.min_kek_version, w.needs_kek_rotation
            FROM workspaces w
            WHERE w.id = $1
            FOR SHARE
        ),
        updated_invitation AS (
            UPDATE workspace_invitations wi
            SET is_used = TRUE
            FROM workspace_guard wg
            WHERE wi.id = $2
              AND wi.workspace_id = wg.id
              AND wg.needs_kek_rotation = FALSE
              AND wi.revoked_at IS NULL
              AND wi.expires_at > NOW()
              AND wi.is_used = FALSE
              AND wi.invited_email = $4
              AND wi.role_id IS NOT NULL
              AND wi.kek_version >= wg.min_kek_version
            RETURNING wi.*
        )
        INSERT INTO workspace_members (workspace_id, user_id, role_id, is_default, joined_at)
        SELECT workspace_id, $3, role_id, false, NOW()
        FROM updated_invitation
        "#,
        inv.workspace_id,
        inv.id,
        user_id.as_uuid(),
        user_email,
    )
    .execute(&mut *tx)
    .await;

    match cte_result {
        Ok(r) if r.rows_affected() == 1 => {
            // Success — new member created
            tx.commit().await?;
            Ok(build_result(
                inv.id,
                inv.workspace_id,
                inv.workspace_name,
                inv.role_name,
            ))
        }
        Ok(_) => {
            // 0 rows — CTE conditions not met
            tx.rollback().await.ok();
            handle_cte_zero_rows(pool, &inv.id, &inv.workspace_id, user_id, user_email, kek_version, || {
                build_result(
                    inv.id,
                    inv.workspace_id,
                    inv.workspace_name.clone(),
                    inv.role_name.clone(),
                )
            })
            .await
        }
        Err(e) => {
            tx.rollback().await.ok();
            handle_cte_error(pool, e, &inv.workspace_id, kek_version, || {
                build_result(
                    inv.id,
                    inv.workspace_id,
                    inv.workspace_name.clone(),
                    inv.role_name.clone(),
                )
            })
            .await
        }
    }
}

/// Step 4 — CTE returned 0 rows.
async fn handle_cte_zero_rows(
    pool: &PgPool,
    invitation_id: &Uuid,
    workspace_id: &Uuid,
    user_id: UserId,
    user_email: &str,
    kek_version: i32,
    build: impl Fn() -> InvitationAcceptanceResult,
) -> Result<InvitationAcceptanceResult, AcceptError> {
    // 4a: Race — user became a member between step 2 and step 3
    let became_member = sqlx::query_scalar!(
        "SELECT 1 AS v FROM workspace_members WHERE workspace_id = $1 AND user_id = $2",
        workspace_id,
        user_id.as_uuid(),
    )
    .fetch_optional(pool)
    .await?
    .is_some();

    if became_member {
        return validate_workspace_for_existing_member(pool, workspace_id, kek_version, build)
            .await;
    }

    // 4b: Re-fetch to determine cause (priority order per design doc)
    let fresh = sqlx::query!(
        r#"
        SELECT i.revoked_at, i.expires_at, i.is_used,
               i.invited_email, i.role_id, i.kek_version as "kek_version!",
               w.needs_kek_rotation, w.min_kek_version
        FROM workspace_invitations i
        JOIN workspaces w ON w.id = i.workspace_id
        WHERE i.id = $1
        "#,
        invitation_id,
    )
    .fetch_optional(pool)
    .await?
    .ok_or(InvitationAcceptanceError::NotFound)?;

    if fresh.revoked_at.is_some() {
        Err(InvitationAcceptanceError::Revoked.into())
    } else if fresh.expires_at <= Utc::now() {
        Err(InvitationAcceptanceError::Expired.into())
    } else if fresh.is_used {
        Err(InvitationAcceptanceError::AlreadyUsed.into())
    } else if fresh.invited_email != user_email {
        Err(InvitationAcceptanceError::EmailMismatch.into())
    } else if fresh.needs_kek_rotation {
        Err(InvitationAcceptanceError::KekRotationInProgress.into())
    } else if fresh.kek_version < fresh.min_kek_version {
        Err(InvitationAcceptanceError::StaleKekVersion.into())
    } else if fresh.role_id.is_none() {
        Err(InvitationAcceptanceError::RoleDeleted.into())
    } else {
        Err(InvitationAcceptanceError::Database(
            "CTE conditions not met but no specific cause found".to_string(),
        )
        .into())
    }
}

/// Step 4 — CTE returned a database error.
async fn handle_cte_error(
    pool: &PgPool,
    e: sqlx::Error,
    workspace_id: &Uuid,
    kek_version: i32,
    build: impl Fn() -> InvitationAcceptanceResult,
) -> Result<InvitationAcceptanceResult, AcceptError> {
    if let sqlx::Error::Database(ref db_err) = e {
        let code = db_err.code().unwrap_or_default();

        // UNIQUE violation (23505) — existing member race
        if code == "23505" {
            return validate_workspace_for_existing_member(pool, workspace_id, kek_version, build)
                .await;
        }

        // FK violation (23503)
        if code == "23503" {
            if db_err.constraint().unwrap_or("").contains("role") {
                return Err(InvitationAcceptanceError::RoleDeleted.into());
            }
            return Err(InvitationAcceptanceError::NotFound.into());
        }

        // Deadlock detected (40P01) — retryable
        if code == "40P01" {
            return Err(InvitationAcceptanceError::Deadlock.into());
        }
    }

    Err(e.into())
}

/// Validate workspace state for existing member path (shared logic).
async fn validate_workspace_for_existing_member(
    pool: &PgPool,
    workspace_id: &Uuid,
    kek_version: i32,
    build: impl Fn() -> InvitationAcceptanceResult,
) -> Result<InvitationAcceptanceResult, AcceptError> {
    let ws = sqlx::query!(
        "SELECT needs_kek_rotation, min_kek_version FROM workspaces WHERE id = $1 FOR SHARE",
        workspace_id,
    )
    .fetch_optional(pool)
    .await?
    .ok_or(InvitationAcceptanceError::NotFound)?;

    if ws.needs_kek_rotation {
        return Err(InvitationAcceptanceError::KekRotationInProgress.into());
    }
    if kek_version < ws.min_kek_version {
        return Err(InvitationAcceptanceError::StaleKekVersion.into());
    }

    Ok(build())
}
