//! Transactional invitation creation
//!
//! Follows the design doc concurrency requirements:
//! 1. FOR SHARE lock on workspace row (serialise with KEK rotation)
//! 2. Validate needs_kek_rotation = false
//! 3. Validate kek_version == MAX(workspace_kek_backups.key_version)
//! 4. INSERT with constraint violation handling

use application::workspace::{InvitationCreationError, InvitationCreationService};
use async_trait::async_trait;
use domain::workspace::WorkspaceInvitation;
use sqlx::PgPool;
use std::sync::Arc;

/// PostgreSQL implementation of InvitationCreationService
#[derive(Clone)]
pub struct PgInvitationCreationService {
    pool: Arc<PgPool>,
}

impl PgInvitationCreationService {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InvitationCreationService for PgInvitationCreationService {
    async fn create_atomic(
        &self,
        invitation: &WorkspaceInvitation,
    ) -> Result<(), InvitationCreationError> {
        create_invitation_atomic(&self.pool, invitation)
            .await
            .map_err(|e| match e {
                CreateError::App(e) => e,
                CreateError::Db(e) => InvitationCreationError::Database(e.to_string()),
            })
    }
}

enum CreateError {
    App(InvitationCreationError),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for CreateError {
    fn from(e: sqlx::Error) -> Self {
        CreateError::Db(e)
    }
}

impl From<InvitationCreationError> for CreateError {
    fn from(e: InvitationCreationError) -> Self {
        CreateError::App(e)
    }
}

async fn create_invitation_atomic(
    pool: &PgPool,
    invitation: &WorkspaceInvitation,
) -> Result<(), CreateError> {
    let workspace_id = invitation.workspace_id.as_uuid();
    let kek_version = invitation.kek_version;

    let mut tx = pool.begin().await?;

    // 1. FOR SHARE lock on workspace row — serialise with KEK rotation UPDATE
    let ws = sqlx::query!(
        "SELECT needs_kek_rotation FROM workspaces WHERE id = $1 FOR SHARE",
        workspace_id,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(InvitationCreationError::WorkspaceNotFound)?;

    if ws.needs_kek_rotation {
        return Err(InvitationCreationError::NeedsKekRotation.into());
    }

    // 2. kek_version must equal MAX(workspace_kek_backups.key_version).
    //    Per design doc: the invitation must be encrypted under the latest KEK version.
    let max_version: Option<i32> = sqlx::query_scalar!(
        "SELECT MAX(key_version) FROM workspace_kek_backups WHERE workspace_id = $1",
        workspace_id,
    )
    .fetch_one(&mut *tx)
    .await?;

    let max_version = max_version.ok_or(InvitationCreationError::NoActiveKek)?;

    if kek_version != max_version {
        return Err(InvitationCreationError::KekVersionMismatch.into());
    }

    // 3. INSERT invitation with constraint violation handling
    let result = sqlx::query!(
        r#"
        INSERT INTO workspace_invitations (
            id, workspace_id, token_hash, token_prefix, role_id,
            invited_by, invited_email, encrypted_kek, kek_nonce, kek_version,
            is_used, revoked_at, expires_at, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        "#,
        invitation.id.as_uuid(),
        workspace_id,
        &invitation.token_hash,
        &invitation.token_prefix,
        invitation.role_id.map(|r| r.as_uuid()),
        invitation.invited_by.as_uuid(),
        &invitation.invited_email,
        &invitation.encrypted_kek[..],
        &invitation.kek_nonce[..],
        invitation.kek_version,
        invitation.is_used,
        invitation.revoked_at,
        invitation.expires_at,
        invitation.created_at,
    )
    .execute(&mut *tx)
    .await;

    match result {
        Ok(_) => {
            tx.commit().await?;
            Ok(())
        }
        Err(sqlx::Error::Database(ref db_err)) => {
            let code = db_err.code().unwrap_or_default();

            // UNIQUE violation (23505)
            if code == "23505" {
                let constraint = db_err.constraint().unwrap_or("");
                if constraint.contains("token_hash") {
                    return Err(InvitationCreationError::TokenHashConflict.into());
                }
                // PK violation (invitation_id)
                return Err(InvitationCreationError::InvitationIdConflict.into());
            }

            // FK violation (23503)
            if code == "23503" {
                let constraint = db_err.constraint().unwrap_or("");
                if constraint.contains("role") {
                    return Err(InvitationCreationError::RoleDeleted.into());
                }
                // workspace_id FK
                return Err(InvitationCreationError::WorkspaceNotFound.into());
            }

            Err(result.unwrap_err().into())
        }
        Err(e) => Err(e.into()),
    }
}
