//! Transactional user registration
//!
//! Handles user registration with all related entities in a single transaction.
//!
//! ## Why SQL here duplicates individual repository INSERT statements
//!
//! The per-entity `insert_*` helpers intentionally use **plain INSERT** (no
//! `ON CONFLICT`).  Registration must be the *first* write for every entity ---
//! a unique-constraint violation means a conflicting registration attempt and
//! should surface as an error, not silently merge.
//!
//! The corresponding repository implementations (e.g. `PgUserRepository::save`)
//! use **UPSERT** (`ON CONFLICT ... DO UPDATE`) because they handle subsequent
//! mutations where the row already exists.

use application::identity::{RegistrationData, RegistrationService, RegistrationServiceError};
use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistrationError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// PostgreSQL implementation of RegistrationService
#[derive(Clone)]
pub struct PgRegistrationService {
    pool: Arc<PgPool>,
}

impl PgRegistrationService {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RegistrationService for PgRegistrationService {
    async fn register_atomic(
        &self,
        data: RegistrationData,
    ) -> Result<(), RegistrationServiceError> {
        register_user_atomic(&self.pool, data).await.map_err(|e| match &e {
            // Detect PostgreSQL unique constraint violations (error code 23505).
            // Only map to Conflict if the constraint is on the users table (email).
            // Other 23505 errors (e.g. workspace slug, device PK) are unexpected
            // during registration and should surface as Database errors.
            RegistrationError::Database(sqlx::Error::Database(db_err))
                if db_err.code().as_deref() == Some("23505")
                    && db_err
                        .constraint()
                        .map_or(false, |c| c.contains("email") || c == "users_pkey") =>
            {
                RegistrationServiceError::Conflict(db_err.message().to_string())
            }
            _ => RegistrationServiceError::Database(e.to_string()),
        })
    }
}

/// Execute user registration in a single transaction
pub async fn register_user_atomic(
    pool: &PgPool,
    data: RegistrationData,
) -> Result<(), RegistrationError> {
    let mut tx = pool.begin().await?;

    insert_user(&mut tx, &data.user).await?;
    insert_user_settings(&mut tx, &data.settings).await?;
    insert_identity_public_key(&mut tx, &data.identity_public_key).await?;
    insert_encrypted_master_key(&mut tx, &data.encrypted_master_key).await?;
    insert_encrypted_identity_key(&mut tx, &data.encrypted_identity_key).await?;
    insert_workspace(&mut tx, &data.workspace).await?;
    for role in [&data.owner_role, &data.admin_role, &data.editor_role, &data.viewer_role] {
        insert_workspace_role(&mut tx, role).await?;
    }
    insert_workspace_member(&mut tx, &data.member).await?;
    insert_device(&mut tx, &data.device).await?;

    tx.commit().await?;
    Ok(())
}

type PgTx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

async fn insert_user(tx: &mut PgTx<'_>, user: &domain::identity::User) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO users (id, email, name, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        user.id.as_uuid(),
        user.email.as_str(),
        &user.name,
        user.created_at,
        user.updated_at,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_user_settings(
    tx: &mut PgTx<'_>,
    settings: &domain::identity::UserSettings,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO user_settings (user_id, theme, locale, editor_vim_mode, editor_font_size, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        settings.user_id.as_uuid(),
        settings.theme.as_str(),
        settings.locale.as_str(),
        settings.editor_vim_mode,
        settings.editor_font_size,
        settings.updated_at,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_identity_public_key(
    tx: &mut PgTx<'_>,
    key: &domain::encryption::UserIdentityPublicKey,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO user_identity_public_keys (user_id, ecdh_public_key, signing_public_key, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        key.user_id.as_uuid(),
        &key.ecdh_public_key,
        &key.signing_public_key,
        key.created_at,
        key.updated_at,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_encrypted_master_key(
    tx: &mut PgTx<'_>,
    key: &domain::encryption::UserEncryptedMasterKey,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO user_encrypted_master_keys (
            user_id, auth_type, encrypted_umk, umk_nonce, salt, kdf_type, kdf_params, auth_key_hash,
            recovery_encrypted_umk, recovery_nonce, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
        key.user_id.as_uuid(),
        key.auth_type.as_str(),
        key.encrypted_umk.as_deref(),
        key.umk_nonce.as_deref(),
        key.salt.as_deref(),
        key.kdf_type.map(|t| t.as_str().to_owned()) as Option<String>,
        key.kdf_params.as_ref().map(sqlx::types::Json) as _,
        key.auth_key_hash.as_deref(),
        &key.recovery_encrypted_umk,
        &key.recovery_nonce,
        key.created_at,
        key.updated_at,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_encrypted_identity_key(
    tx: &mut PgTx<'_>,
    key: &domain::encryption::UserEncryptedIdentityKey,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO user_encrypted_identity_keys (
            user_id, encrypted_ecdh_private, encrypted_ecdh_private_nonce,
            encrypted_signing_private, encrypted_signing_private_nonce, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
        key.user_id.as_uuid(),
        &key.encrypted_ecdh_private,
        &key.encrypted_ecdh_private_nonce,
        &key.encrypted_signing_private,
        &key.encrypted_signing_private_nonce,
        key.created_at,
        key.updated_at,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_workspace(
    tx: &mut PgTx<'_>,
    workspace: &domain::workspace::Workspace,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO workspaces (id, name, slug, description, icon, owner_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        workspace.id.as_uuid(),
        &workspace.name,
        workspace.slug.as_str(),
        workspace.description.as_deref(),
        workspace.icon.as_deref(),
        workspace.owner_id.as_uuid(),
        workspace.created_at,
        workspace.updated_at,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_workspace_role(
    tx: &mut PgTx<'_>,
    role: &domain::workspace::WorkspaceRole,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO workspace_roles (id, workspace_id, name, base_role, is_default, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        role.id.as_uuid(),
        role.workspace_id.as_uuid(),
        &role.name,
        role.base_role.as_str(),
        role.is_default,
        role.created_at,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_workspace_member(
    tx: &mut PgTx<'_>,
    member: &domain::workspace::WorkspaceMember,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO workspace_members (workspace_id, user_id, role_id, is_default, joined_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        member.workspace_id.as_uuid(),
        member.user_id.as_uuid(),
        member.role_id.as_uuid(),
        member.is_default,
        member.joined_at,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_device(
    tx: &mut PgTx<'_>,
    device: &domain::encryption::Device,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO devices (id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                            identity_signature, client_nonce, last_seen_at, created_at, revoked_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
        device.id.as_uuid(),
        device.user_id.as_uuid(),
        &device.name,
        device.device_type.as_str(),
        &device.ecdh_public_key,
        &device.signing_public_key,
        &device.identity_signature,
        &device.client_nonce,
        device.last_seen_at,
        device.created_at,
        device.revoked_at,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}
