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
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::sync::Arc;
use thiserror::Error;

use crate::identity::services::{RegistrationData, RegistrationService};

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
    pub user: User,
    pub workspace: Workspace,
    pub device: Device,
}

/// Register password user error
#[derive(Debug, Error)]
pub enum RegisterPasswordUserAtomicError<UR: std::error::Error, WR: std::error::Error> {
    #[error("invalid email: {0}")]
    InvalidEmail(#[from] EmailError),

    #[error("email already exists")]
    EmailAlreadyExists,

    #[error("invalid auth key")]
    InvalidAuthKey,

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

impl<UR: std::error::Error, WR: std::error::Error> RegisterPasswordUserAtomicError<UR, WR> {
    pub fn is_conflict(&self) -> bool {
        matches!(self, RegisterPasswordUserAtomicError::EmailAlreadyExists)
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            RegisterPasswordUserAtomicError::InvalidEmail(_)
                | RegisterPasswordUserAtomicError::InvalidAuthKey
                | RegisterPasswordUserAtomicError::InvalidKeyLength
                | RegisterPasswordUserAtomicError::InvalidIdentitySignature
        )
    }
}

/// Atomic register password user handler
///
/// Uses RegistrationService for transactional persistence.
pub struct RegisterPasswordUserAtomicHandler<U, WR, RS> {
    user_repo: Arc<U>,
    workspace_repo: Arc<WR>,
    registration_service: Arc<RS>,
}

impl<U, WR, RS> RegisterPasswordUserAtomicHandler<U, WR, RS>
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
        // Validate email
        let email = Email::new(&command.email)?;

        // Check if email already exists
        if self
            .user_repo
            .email_exists(&email)
            .await
            .map_err(RegisterPasswordUserAtomicError::UserRepository)?
        {
            return Err(RegisterPasswordUserAtomicError::EmailAlreadyExists);
        }

        // Validate key lengths
        if command.ecdh_public_key.len() != 32 || command.signing_public_key.len() != 32 {
            return Err(RegisterPasswordUserAtomicError::InvalidKeyLength);
        }
        // Salt is 16 bytes per spec
        if command.salt.len() != 16 {
            return Err(RegisterPasswordUserAtomicError::InvalidKeyLength);
        }
        // Validate device key lengths
        if command.device_ecdh_public_key.len() != 32
            || command.device_signing_public_key.len() != 32
        {
            return Err(RegisterPasswordUserAtomicError::InvalidKeyLength);
        }
        // Validate device client nonce (16 bytes) and identity signature (64 bytes for Ed25519)
        if command.device_client_nonce.len() != 16 || command.device_identity_signature.len() != 64
        {
            return Err(RegisterPasswordUserAtomicError::InvalidKeyLength);
        }

        // Verify identity signature over device keys
        // Signature is over: device_signing_pk || device_ecdh_pk || client_nonce
        verify_device_identity_signature(
            &command.signing_public_key,
            &command.device_signing_public_key,
            &command.device_ecdh_public_key,
            &command.device_client_nonce,
            &command.device_identity_signature,
        )
        .map_err(|_| RegisterPasswordUserAtomicError::InvalidIdentitySignature)?;

        // Hash the authKey with bcrypt
        let auth_key_hash = bcrypt::hash(&command.auth_key, bcrypt::DEFAULT_COST)
            .map_err(|_| RegisterPasswordUserAtomicError::BcryptError)?;

        // Create user with client-provided ID (for AAD binding)
        let user = User::with_id(command.user_id, email, command.name.clone());

        // Create settings
        let settings = UserSettings::new(user.id);

        // Create identity public key
        let public_keys = PublicKeyPair::new(
            command.ecdh_public_key.clone(),
            command.signing_public_key.clone(),
        );
        let identity_public_key = UserIdentityPublicKey::new(user.id, public_keys);

        // Create encrypted master key
        let encrypted_master_key =
            UserEncryptedMasterKey::new_password_user(PasswordUserMasterKeyParams {
                user_id: user.id,
                encrypted_umk: command.encrypted_umk,
                umk_nonce: command.umk_nonce,
                salt: command.salt,
                kdf_params: KdfParams::default(),
                auth_key_hash,
                recovery_encrypted_umk: command.recovery_encrypted_umk,
                recovery_nonce: command.recovery_nonce,
            });

        // Create encrypted identity key
        let encrypted_identity_key = UserEncryptedIdentityKey::new(
            user.id,
            command.encrypted_ecdh_private,
            command.encrypted_ecdh_private_nonce,
            command.encrypted_signing_private,
            command.encrypted_signing_private_nonce,
        );

        // Generate slug from user name
        let slug = generate_slug(&command.name)?;

        // Check if slug exists, if so, append a random suffix
        let final_slug = self.ensure_unique_slug(slug).await?;

        // Create workspace
        let workspace_name = format!("{}'s Workspace", command.name);
        let workspace = Workspace::new(workspace_name, final_slug, user.id);

        // Create roles
        let owner_role = WorkspaceRole::owner(workspace.id);
        let editor_role = WorkspaceRole::editor(workspace.id);
        let viewer_role = WorkspaceRole::viewer(workspace.id);

        // Create member
        let member = WorkspaceMember::new_owner(workspace.id, user.id, owner_role.id);

        // Create first device for PoP authentication
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

        // Prepare registration data
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

        // Execute atomic registration
        self.registration_service
            .register_atomic(registration_data)
            .await
            .map_err(|e| RegisterPasswordUserAtomicError::Transaction(e.to_string()))?;

        Ok(RegisterPasswordUserAtomicResult {
            user,
            workspace,
            device,
        })
    }

    async fn ensure_unique_slug(
        &self,
        base_slug: Slug,
    ) -> Result<Slug, RegisterPasswordUserAtomicError<U::Error, WR::Error>> {
        let exists = self
            .workspace_repo
            .slug_exists(&base_slug)
            .await
            .map_err(RegisterPasswordUserAtomicError::WorkspaceRepository)?;

        if !exists {
            return Ok(base_slug);
        }

        // Try with random suffixes
        for _ in 0..10 {
            let suffix = generate_random_suffix();
            let new_slug_str = format!("{}-{}", base_slug.as_str(), suffix);
            if let Ok(new_slug) = Slug::new(new_slug_str) {
                let exists = self
                    .workspace_repo
                    .slug_exists(&new_slug)
                    .await
                    .map_err(RegisterPasswordUserAtomicError::WorkspaceRepository)?;

                if !exists {
                    return Ok(new_slug);
                }
            }
        }

        // Fallback: use UUID-based slug
        let uuid_slug = Slug::new(format!("workspace-{}", uuid::Uuid::now_v7()))?;
        Ok(uuid_slug)
    }
}

/// Generate a URL-safe slug from a name
fn generate_slug(name: &str) -> Result<Slug, SlugError> {
    let slug_str: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    if slug_str.is_empty() {
        return Slug::new("workspace");
    }

    Slug::new(slug_str)
}

/// Generate a random 4-character suffix
fn generate_random_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:04x}", nanos % 0xFFFF)
}

/// Verify identity signature over device keys
///
/// The signature payload is: device_signing_pk || device_ecdh_pk || client_nonce
/// This proves the user's identity key approved this device's key material.
fn verify_device_identity_signature(
    identity_signing_pk: &[u8],
    device_signing_pk: &[u8],
    device_ecdh_pk: &[u8],
    client_nonce: &[u8],
    signature: &[u8],
) -> Result<(), ed25519_dalek::SignatureError> {
    // Parse identity signing public key
    let pk_bytes: [u8; 32] = identity_signing_pk
        .try_into()
        .map_err(|_| ed25519_dalek::SignatureError::new())?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)?;

    // Build signature payload: device_signing_pk || device_ecdh_pk || client_nonce
    let mut payload = Vec::with_capacity(32 + 32 + 16);
    payload.extend_from_slice(device_signing_pk);
    payload.extend_from_slice(device_ecdh_pk);
    payload.extend_from_slice(client_nonce);

    // Parse signature
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| ed25519_dalek::SignatureError::new())?;
    let sig = Signature::from_bytes(&sig_bytes);

    // Verify signature
    verifying_key.verify(&payload, &sig)
}
