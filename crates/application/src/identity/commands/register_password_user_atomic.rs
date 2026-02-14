//! Atomic register password user command
//!
//! This module provides atomic (transactional) user registration.
//! The actual transaction handling is delegated to the infrastructure layer
//! via the RegistrationService trait.

use domain::encryption::{
    Device, DeviceType, KdfParams, PasswordUserMasterKeyParams, PublicKeyPair,
    UserEncryptedIdentityKey, UserEncryptedMasterKey, UserIdentityPublicKey,
};
use domain::identity::{Email, EmailError, User, UserRepository, UserSettings};
use domain::workspace::{
    Slug, SlugError, Workspace, WorkspaceMember, WorkspaceRepository, WorkspaceRole,
};
use domain::signature::{build_signature_message, SignatureAction};
use std::sync::Arc;
use thiserror::Error;

use crate::dto::{DeviceDto, UserDto, WorkspaceDto};
use crate::identity::services::{RegistrationData, RegistrationService};
use crate::util::slug::{ensure_unique_workspace_slug, generate_workspace_slug};

/// Register password user command (atomic version)
#[derive(Debug)]
pub struct RegisterPasswordUserAtomicCommand {
    // Client-generated user ID (for AAD binding)
    pub user_id: uuid::Uuid,

    // Basic info
    pub email: String,
    pub name: String,

    // authKey for login (will be bcrypt hashed on server)
    pub auth_key: String,

    // Salt for KDF (client-generated, 16 bytes per spec)
    pub salt: Vec<u8>,

    // Encrypted UMK (encrypted with PUK derived from password)
    pub encrypted_umk: Vec<u8>,
    pub umk_nonce: Vec<u8>,

    // Recovery key encrypted UMK
    pub recovery_encrypted_umk: Vec<u8>,
    pub recovery_nonce: Vec<u8>,

    // Identity public keys
    pub ecdh_public_key: Vec<u8>,
    pub signing_public_key: Vec<u8>,

    // Identity private keys (encrypted with UMK)
    pub encrypted_ecdh_private: Vec<u8>,
    pub encrypted_ecdh_private_nonce: Vec<u8>,
    pub encrypted_signing_private: Vec<u8>,
    pub encrypted_signing_private_nonce: Vec<u8>,

    // First device info (for PoP authentication)
    pub device_name: String,
    pub device_type: DeviceType,
    pub device_ecdh_public_key: Vec<u8>,
    pub device_signing_public_key: Vec<u8>,
    /// Client nonce for device (16 bytes)
    pub device_client_nonce: Vec<u8>,
    /// Identity signature over device keys (device_signing_pk || device_ecdh_pk || client_nonce)
    pub device_identity_signature: Vec<u8>,
}

/// Register password user result
#[derive(Debug)]
pub struct RegisterPasswordUserAtomicResult {
    pub user: UserDto,
    pub workspace: WorkspaceDto,
    pub device: DeviceDto,
}

/// Register password user error
#[derive(Debug, Error)]
pub enum RegisterPasswordUserAtomicError<UR: std::error::Error, WR: std::error::Error> {
    #[error("invalid email: {0}")]
    InvalidEmail(#[from] EmailError),

    #[error("email already exists")]
    EmailAlreadyExists,

    #[error("bcrypt error")]
    BcryptError,

    #[error("invalid key length")]
    InvalidKeyLength,

    #[error("invalid identity signature")]
    InvalidIdentitySignature,

    #[error("invalid slug: {0}")]
    InvalidSlug(#[from] SlugError),

    #[error("user repository error: {0}")]
    UserRepository(UR),

    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),

    #[error("registration transaction error: {0}")]
    Transaction(String),
}

impl<UR: std::error::Error, WR: std::error::Error> crate::types::AppError for RegisterPasswordUserAtomicError<UR, WR> {
    fn is_conflict(&self) -> bool {
        matches!(self, RegisterPasswordUserAtomicError::EmailAlreadyExists)
    }

    fn is_invalid_input(&self) -> bool {
        matches!(
            self,
            RegisterPasswordUserAtomicError::InvalidEmail(_)
                | RegisterPasswordUserAtomicError::InvalidKeyLength
                | RegisterPasswordUserAtomicError::InvalidIdentitySignature
        )
    }
}

/// Atomic register password user handler
///
/// Uses RegistrationService for transactional persistence.
pub struct RegisterPasswordUserAtomicHandler<U: ?Sized, WR: ?Sized, RS: ?Sized> {
    user_repo: Arc<U>,
    workspace_repo: Arc<WR>,
    registration_service: Arc<RS>,
}

impl<U: ?Sized, WR: ?Sized, RS: ?Sized> RegisterPasswordUserAtomicHandler<U, WR, RS>
where
    U: UserRepository,
    WR: WorkspaceRepository,
    RS: RegistrationService,
{
    pub fn new(user_repo: Arc<U>, workspace_repo: Arc<WR>, registration_service: Arc<RS>) -> Self {
        Self {
            user_repo,
            workspace_repo,
            registration_service,
        }
    }

    pub async fn handle(
        &self,
        command: RegisterPasswordUserAtomicCommand,
    ) -> Result<
        RegisterPasswordUserAtomicResult,
        RegisterPasswordUserAtomicError<U::Error, WR::Error>,
    > {
        // 1. Validate input
        let email = self.validate_input(&command).await?;

        // 2. Hash the authKey with bcrypt
        let auth_key_hash = bcrypt::hash(&command.auth_key, bcrypt::DEFAULT_COST)
            .map_err(|_| RegisterPasswordUserAtomicError::BcryptError)?;

        // 3. Build user-related aggregates
        let (user, settings, identity_public_key, encrypted_master_key, encrypted_identity_key) =
            Self::build_user_data(&command, email, &auth_key_hash);

        // 4. Build workspace-related aggregates
        let slug = generate_workspace_slug(&command.name)?;
        let final_slug = self.ensure_unique_slug(slug).await?;
        let (workspace, owner_role, editor_role, viewer_role, member) =
            Self::build_workspace_data(user.id, &command.name, final_slug);

        // 5. Build device
        let device_public_keys = PublicKeyPair::new(
            command.device_ecdh_public_key.clone(),
            command.device_signing_public_key.clone(),
        );
        let device = Device::new(
            user.id,
            command.device_name,
            command.device_type,
            device_public_keys,
            command.device_identity_signature,
            command.device_client_nonce,
        );

        // 6. Execute atomic registration
        let registration_data = RegistrationData {
            user: user.clone(),
            settings,
            identity_public_key,
            encrypted_master_key,
            encrypted_identity_key,
            workspace: workspace.clone(),
            owner_role,
            editor_role,
            viewer_role,
            member,
            device: device.clone(),
        };

        self.registration_service
            .register_atomic(registration_data)
            .await
            .map_err(|e| match e {
                crate::identity::services::RegistrationServiceError::Conflict(_) => {
                    RegisterPasswordUserAtomicError::EmailAlreadyExists
                }
                other => RegisterPasswordUserAtomicError::Transaction(other.to_string()),
            })?;

        Ok(RegisterPasswordUserAtomicResult {
            user: user.into(),
            workspace: workspace.into(),
            device: device.into(),
        })
    }

    /// Validate email, key lengths, and identity signature.
    ///
    /// NOTE: Presentation layer also validates wire format and key sizes
    /// (defense-in-depth). These checks remain as transport-independent
    /// business-rule preconditions.
    async fn validate_input(
        &self,
        command: &RegisterPasswordUserAtomicCommand,
    ) -> Result<Email, RegisterPasswordUserAtomicError<U::Error, WR::Error>> {
        let email = Email::new(&command.email)?;

        if self
            .user_repo
            .email_exists(&email)
            .await
            .map_err(RegisterPasswordUserAtomicError::UserRepository)?
        {
            return Err(RegisterPasswordUserAtomicError::EmailAlreadyExists);
        }

        // Identity key lengths (32 bytes each for X25519/Ed25519)
        if command.ecdh_public_key.len() != 32 || command.signing_public_key.len() != 32 {
            return Err(RegisterPasswordUserAtomicError::InvalidKeyLength);
        }
        if command.salt.len() != 16 {
            return Err(RegisterPasswordUserAtomicError::InvalidKeyLength);
        }
        // Device key lengths
        if command.device_ecdh_public_key.len() != 32
            || command.device_signing_public_key.len() != 32
        {
            return Err(RegisterPasswordUserAtomicError::InvalidKeyLength);
        }
        if command.device_client_nonce.len() != 16 || command.device_identity_signature.len() != 64
        {
            return Err(RegisterPasswordUserAtomicError::InvalidKeyLength);
        }

        // Reject low-order / small-order public keys (domain cryptographic invariant)
        use domain::crypto_validation::{is_valid_x25519_public_key, is_valid_ed25519_public_key};
        if !is_valid_x25519_public_key(&command.ecdh_public_key)
            || !is_valid_x25519_public_key(&command.device_ecdh_public_key)
        {
            return Err(RegisterPasswordUserAtomicError::InvalidKeyLength);
        }
        if !is_valid_ed25519_public_key(&command.signing_public_key)
            || !is_valid_ed25519_public_key(&command.device_signing_public_key)
        {
            return Err(RegisterPasswordUserAtomicError::InvalidKeyLength);
        }

        verify_device_identity_signature(
            &command.signing_public_key,
            &command.device_signing_public_key,
            &command.device_ecdh_public_key,
            &command.device_client_nonce,
            &command.device_identity_signature,
        )
        .map_err(|_| RegisterPasswordUserAtomicError::InvalidIdentitySignature)?;

        Ok(email)
    }

    /// Build user, settings, identity public key, encrypted master key, and encrypted identity key.
    fn build_user_data(
        command: &RegisterPasswordUserAtomicCommand,
        email: Email,
        auth_key_hash: &str,
    ) -> (User, UserSettings, UserIdentityPublicKey, UserEncryptedMasterKey, UserEncryptedIdentityKey) {
        let user = User::with_id(command.user_id, email, command.name.clone());
        let settings = UserSettings::new(user.id);

        let public_keys = PublicKeyPair::new(
            command.ecdh_public_key.clone(),
            command.signing_public_key.clone(),
        );
        let identity_public_key = UserIdentityPublicKey::new(user.id, public_keys);

        let encrypted_master_key =
            UserEncryptedMasterKey::new_password_user(PasswordUserMasterKeyParams {
                user_id: user.id,
                encrypted_umk: command.encrypted_umk.clone(),
                umk_nonce: command.umk_nonce.clone(),
                salt: command.salt.clone(),
                kdf_params: KdfParams::default(),
                auth_key_hash: auth_key_hash.to_string(),
                recovery_encrypted_umk: command.recovery_encrypted_umk.clone(),
                recovery_nonce: command.recovery_nonce.clone(),
            });

        let encrypted_identity_key = UserEncryptedIdentityKey::new(
            user.id,
            command.encrypted_ecdh_private.clone(),
            command.encrypted_ecdh_private_nonce.clone(),
            command.encrypted_signing_private.clone(),
            command.encrypted_signing_private_nonce.clone(),
        );

        (user, settings, identity_public_key, encrypted_master_key, encrypted_identity_key)
    }

    /// Build workspace, roles, and member for the new user.
    fn build_workspace_data(
        user_id: domain::identity::UserId,
        name: &str,
        slug: Slug,
    ) -> (Workspace, WorkspaceRole, WorkspaceRole, WorkspaceRole, WorkspaceMember) {
        let workspace_name = format!("{}'s Workspace", name);
        let workspace = Workspace::new(workspace_name, slug, user_id);

        let owner_role = WorkspaceRole::owner(workspace.id);
        let editor_role = WorkspaceRole::editor(workspace.id);
        let viewer_role = WorkspaceRole::viewer(workspace.id);

        let member = WorkspaceMember::new_owner(workspace.id, user_id, owner_role.id);

        (workspace, owner_role, editor_role, viewer_role, member)
    }

    async fn ensure_unique_slug(
        &self,
        base_slug: Slug,
    ) -> Result<Slug, RegisterPasswordUserAtomicError<U::Error, WR::Error>> {
        match ensure_unique_workspace_slug(&self.workspace_repo, base_slug)
            .await
            .map_err(RegisterPasswordUserAtomicError::WorkspaceRepository)?
        {
            Some(slug) => Ok(slug),
            None => {
                // Fallback: use UUID-based slug
                let uuid_slug = Slug::new(format!("workspace-{}", uuid::Uuid::now_v7()))?;
                Ok(uuid_slug)
            }
        }
    }
}

/// Verify identity signature over device keys using JCS (JSON Canonicalization Scheme)
///
/// Per spec: All signatures use the signature protocol format with
/// canonicalized JSON including protocol, version, and action fields.
/// This proves the user's identity key approved this device's key material.
fn verify_device_identity_signature(
    identity_signing_pk: &[u8],
    device_signing_pk: &[u8],
    device_ecdh_pk: &[u8],
    client_nonce: &[u8],
    signature: &[u8],
) -> Result<(), crate::util::signature_verification::SignatureVerificationError> {
    use serde::Serialize;

    // Build JCS signature payload
    #[derive(Serialize)]
    struct RegistrationPayload {
        client_nonce: String,
        device_ecdh_public_key: String,
        device_signing_public_key: String,
    }

    let message = build_signature_message(
        SignatureAction::DeviceRegistration,
        &RegistrationPayload {
            device_signing_public_key: base64_url::encode(device_signing_pk),
            device_ecdh_public_key: base64_url::encode(device_ecdh_pk),
            client_nonce: base64_url::encode(client_nonce),
        },
    )
    .map_err(|_| crate::util::signature_verification::SignatureVerificationError::VerificationFailed)?;

    crate::util::signature_verification::verify_ed25519_signature(
        identity_signing_pk,
        signature,
        &message,
    )
}
