//! Transactional user registration
//!
//! Handles user registration with all related entities in a single transaction.

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
        register_user_atomic(&self.pool, data)
            .await
            .map_err(|e| RegistrationServiceError::Database(e.to_string()))
    }
}

/// Execute user registration in a single transaction
pub async fn register_user_atomic(
    pool: &PgPool,
    data: RegistrationData,
) -> Result<(), RegistrationError> {
    let mut tx = pool.begin().await?;

    // 1. Create user
    sqlx::query(
        r#"
        INSERT INTO users (id, email, name, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(data.user.id.as_uuid())
    .bind(data.user.email.as_str())
    .bind(&data.user.name)
    .bind(data.user.created_at)
    .bind(data.user.updated_at)
    .execute(&mut *tx)
    .await?;

    // 2. Create user settings
    sqlx::query(
        r#"
        INSERT INTO user_settings (user_id, theme, locale, editor_vim_mode, editor_font_size, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(data.settings.user_id.as_uuid())
    .bind(data.settings.theme.as_str())
    .bind(data.settings.locale.as_str())
    .bind(data.settings.editor_vim_mode)
    .bind(data.settings.editor_font_size)
    .bind(data.settings.updated_at)
    .execute(&mut *tx)
    .await?;

    // 3. Create identity public key
    sqlx::query(
        r#"
        INSERT INTO user_identity_public_keys (user_id, ecdh_public_key, signing_public_key, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(data.identity_public_key.user_id.as_uuid())
    .bind(&data.identity_public_key.ecdh_public_key)
    .bind(&data.identity_public_key.signing_public_key)
    .bind(data.identity_public_key.created_at)
    .bind(data.identity_public_key.updated_at)
    .execute(&mut *tx)
    .await?;

    // 4. Create encrypted master key
    sqlx::query(
        r#"
        INSERT INTO user_encrypted_master_keys (
            user_id, auth_type, encrypted_umk, umk_nonce, salt, kdf_type, kdf_params, auth_key_hash,
            recovery_encrypted_umk, recovery_nonce, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(data.encrypted_master_key.user_id.as_uuid())
    .bind(data.encrypted_master_key.auth_type.as_str())
    .bind(&data.encrypted_master_key.encrypted_umk)
    .bind(&data.encrypted_master_key.umk_nonce)
    .bind(&data.encrypted_master_key.salt)
    .bind(data.encrypted_master_key.kdf_type.map(|t| t.as_str()))
    .bind(
        data.encrypted_master_key
            .kdf_params
            .as_ref()
            .map(sqlx::types::Json),
    )
    .bind(&data.encrypted_master_key.auth_key_hash)
    .bind(&data.encrypted_master_key.recovery_encrypted_umk)
    .bind(&data.encrypted_master_key.recovery_nonce)
    .bind(data.encrypted_master_key.created_at)
    .bind(data.encrypted_master_key.updated_at)
    .execute(&mut *tx)
    .await?;

    // 5. Create encrypted identity key
    sqlx::query(
        r#"
        INSERT INTO user_encrypted_identity_keys (
            user_id, encrypted_ecdh_private, encrypted_ecdh_private_nonce,
            encrypted_signing_private, encrypted_signing_private_nonce, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(data.encrypted_identity_key.user_id.as_uuid())
    .bind(&data.encrypted_identity_key.encrypted_ecdh_private)
    .bind(&data.encrypted_identity_key.encrypted_ecdh_private_nonce)
    .bind(&data.encrypted_identity_key.encrypted_signing_private)
    .bind(&data.encrypted_identity_key.encrypted_signing_private_nonce)
    .bind(data.encrypted_identity_key.created_at)
    .bind(data.encrypted_identity_key.updated_at)
    .execute(&mut *tx)
    .await?;

    // 6. Create workspace
    sqlx::query(
        r#"
        INSERT INTO workspaces (id, name, slug, description, icon, owner_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(data.workspace.id.as_uuid())
    .bind(&data.workspace.name)
    .bind(data.workspace.slug.as_str())
    .bind(&data.workspace.description)
    .bind(&data.workspace.icon)
    .bind(data.workspace.owner_id.as_uuid())
    .bind(data.workspace.created_at)
    .bind(data.workspace.updated_at)
    .execute(&mut *tx)
    .await?;

    // 7. Create workspace roles
    for role in [&data.owner_role, &data.editor_role, &data.viewer_role] {
        sqlx::query(
            r#"
            INSERT INTO workspace_roles (id, workspace_id, name, base_role, is_default, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(role.id.as_uuid())
        .bind(role.workspace_id.as_uuid())
        .bind(&role.name)
        .bind(role.base_role.as_str())
        .bind(role.is_default)
        .bind(role.created_at)
        .execute(&mut *tx)
        .await?;
    }

    // 8. Create workspace member
    sqlx::query(
        r#"
        INSERT INTO workspace_members (workspace_id, user_id, role_id, is_default, joined_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(data.member.workspace_id.as_uuid())
    .bind(data.member.user_id.as_uuid())
    .bind(data.member.role_id.as_uuid())
    .bind(data.member.is_default)
    .bind(data.member.joined_at)
    .execute(&mut *tx)
    .await?;

    // 9. Create first device for PoP authentication
    sqlx::query(
        r#"
        INSERT INTO devices (id, user_id, name, device_type, ecdh_public_key, signing_public_key,
                            identity_signature, client_nonce, last_seen_at, created_at, revoked_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(data.device.id.as_uuid())
    .bind(data.device.user_id.as_uuid())
    .bind(&data.device.name)
    .bind(data.device.device_type.as_str())
    .bind(&data.device.ecdh_public_key)
    .bind(&data.device.signing_public_key)
    .bind(&data.device.identity_signature)
    .bind(&data.device.client_nonce)
    .bind(data.device.last_seen_at)
    .bind(data.device.created_at)
    .bind(data.device.revoked_at)
    .execute(&mut *tx)
    .await?;

    // Commit transaction
    tx.commit().await?;

    Ok(())
}
