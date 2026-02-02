//! Atomic register password user command
//!
//! This module provides atomic (transactional) user registration.
//! The actual transaction handling is delegated to the infrastructure layer
//! via the RegistrationService trait.

use std::sync::Arc;
use domain::encryption::{
    KdfParams, PublicKeyPair, UserEncryptedIdentityKey, UserEncryptedMasterKey, UserIdentityPublicKey,
};
use domain::identity::{Email, EmailError, User, UserRepository, UserSettings};
use domain::workspace::{Slug, SlugError, Workspace, WorkspaceMember, WorkspaceRole, WorkspaceRepository};
use thiserror::Error;

use crate::identity::services::{RegistrationData, RegistrationService};

/// Register password user command (atomic version)
#[derive(Debug)]
pub struct RegisterPasswordUserAtomicCommand {
    // Basic info
    pub email: String,
    pub name: String,

    // authKey for login (will be bcrypt hashed on server)
    pub auth_key: String,

    // Salt for KDF (client-generated, 32 bytes)
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
}

/// Register password user result
#[derive(Debug)]
pub struct RegisterPasswordUserAtomicResult {
    pub user: User,
    pub workspace: Workspace,
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
    pub fn new(
        user_repo: Arc<U>,
        workspace_repo: Arc<WR>,
        registration_service: Arc<RS>,
    ) -> Self {
        Self {
            user_repo,
            workspace_repo,
            registration_service,
        }
    }

    pub async fn handle(
        &self,
        command: RegisterPasswordUserAtomicCommand,
    ) -> Result<RegisterPasswordUserAtomicResult, RegisterPasswordUserAtomicError<U::Error, WR::Error>> {
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
        if command.salt.len() != 32 {
            return Err(RegisterPasswordUserAtomicError::InvalidKeyLength);
        }

        // Hash the authKey with bcrypt
        let auth_key_hash = bcrypt::hash(&command.auth_key, bcrypt::DEFAULT_COST)
            .map_err(|_| RegisterPasswordUserAtomicError::BcryptError)?;

        // Create user
        let user = User::new(email, command.name.clone());

        // Create settings
        let settings = UserSettings::new(user.id);

        // Create identity public key
        let public_keys = PublicKeyPair::new(
            command.ecdh_public_key.clone(),
            command.signing_public_key.clone(),
        );
        let identity_public_key = UserIdentityPublicKey::new(user.id, public_keys);

        // Create encrypted master key
        let encrypted_master_key = UserEncryptedMasterKey::new_password_user(
            user.id,
            command.encrypted_umk,
            command.umk_nonce,
            command.salt,
            KdfParams::default(),
            auth_key_hash,
            command.recovery_encrypted_umk,
            command.recovery_nonce,
        );

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
        };

        // Execute atomic registration
        self.registration_service
            .register_atomic(registration_data)
            .await
            .map_err(|e| RegisterPasswordUserAtomicError::Transaction(e.to_string()))?;

        Ok(RegisterPasswordUserAtomicResult { user, workspace })
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
