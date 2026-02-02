//! Register password user command
//!
//! Complete registration for password-based users including all encryption keys.
//! Also creates a personal workspace for the user.

use domain::encryption::{
    KdfParams, PasswordUserMasterKeyParams, PublicKeyPair, UserEncryptedIdentityKey,
    UserEncryptedIdentityKeyRepository, UserEncryptedMasterKey, UserEncryptedMasterKeyRepository,
    UserIdentityPublicKey, UserIdentityPublicKeyRepository,
};
use domain::identity::{
    Email, EmailError, User, UserRepository, UserSettings, UserSettingsRepository,
};
use domain::workspace::{
    Slug, SlugError, Workspace, WorkspaceMember, WorkspaceMemberRepository, WorkspaceRepository,
    WorkspaceRole, WorkspaceRoleRepository,
};
use std::sync::Arc;
use thiserror::Error;

/// Register password user command
#[derive(Debug)]
pub struct RegisterPasswordUserCommand {
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
}

/// Register password user result
#[derive(Debug)]
pub struct RegisterPasswordUserResult {
    pub user: User,
    pub workspace: Workspace,
}

/// Register password user error
#[derive(Debug, Error)]
pub enum RegisterPasswordUserError<
    UR: std::error::Error,
    US: std::error::Error,
    UIP: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
    WR: std::error::Error,
    WMR: std::error::Error,
    WRR: std::error::Error,
> {
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

    #[error("settings repository error: {0}")]
    SettingsRepository(US),

    #[error("identity public key repository error: {0}")]
    IdentityPublicKeyRepository(UIP),

    #[error("encrypted master key repository error: {0}")]
    EncryptedMasterKeyRepository(UEM),

    #[error("encrypted identity key repository error: {0}")]
    EncryptedIdentityKeyRepository(UEI),

    #[error("workspace repository error: {0}")]
    WorkspaceRepository(WR),

    #[error("workspace member repository error: {0}")]
    WorkspaceMemberRepository(WMR),

    #[error("workspace role repository error: {0}")]
    WorkspaceRoleRepository(WRR),
}

impl<UR, US, UIP, UEM, UEI, WR, WMR, WRR>
    RegisterPasswordUserError<UR, US, UIP, UEM, UEI, WR, WMR, WRR>
where
    UR: std::error::Error,
    US: std::error::Error,
    UIP: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
    WR: std::error::Error,
    WMR: std::error::Error,
    WRR: std::error::Error,
{
    pub fn is_conflict(&self) -> bool {
        matches!(self, RegisterPasswordUserError::EmailAlreadyExists)
    }

    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            RegisterPasswordUserError::InvalidEmail(_)
                | RegisterPasswordUserError::InvalidAuthKey
                | RegisterPasswordUserError::InvalidKeyLength
        )
    }
}

/// Parameters for creating RegisterPasswordUserHandler
pub struct RegisterPasswordUserHandlerParams<U, US, UIP, UEM, UEI, WR, WMR, WRR> {
    pub user_repo: Arc<U>,
    pub settings_repo: Arc<US>,
    pub identity_public_key_repo: Arc<UIP>,
    pub encrypted_master_key_repo: Arc<UEM>,
    pub encrypted_identity_key_repo: Arc<UEI>,
    pub workspace_repo: Arc<WR>,
    pub workspace_member_repo: Arc<WMR>,
    pub workspace_role_repo: Arc<WRR>,
}

/// Register password user handler
pub struct RegisterPasswordUserHandler<U, US, UIP, UEM, UEI, WR, WMR, WRR> {
    user_repo: Arc<U>,
    settings_repo: Arc<US>,
    identity_public_key_repo: Arc<UIP>,
    encrypted_master_key_repo: Arc<UEM>,
    encrypted_identity_key_repo: Arc<UEI>,
    workspace_repo: Arc<WR>,
    workspace_member_repo: Arc<WMR>,
    workspace_role_repo: Arc<WRR>,
}

impl<U, US, UIP, UEM, UEI, WR, WMR, WRR>
    RegisterPasswordUserHandler<U, US, UIP, UEM, UEI, WR, WMR, WRR>
where
    U: UserRepository,
    US: UserSettingsRepository,
    UIP: UserIdentityPublicKeyRepository,
    UEM: UserEncryptedMasterKeyRepository,
    UEI: UserEncryptedIdentityKeyRepository,
    WR: WorkspaceRepository,
    WMR: WorkspaceMemberRepository,
    WRR: WorkspaceRoleRepository,
{
    pub fn new(
        params: RegisterPasswordUserHandlerParams<U, US, UIP, UEM, UEI, WR, WMR, WRR>,
    ) -> Self {
        Self {
            user_repo: params.user_repo,
            settings_repo: params.settings_repo,
            identity_public_key_repo: params.identity_public_key_repo,
            encrypted_master_key_repo: params.encrypted_master_key_repo,
            encrypted_identity_key_repo: params.encrypted_identity_key_repo,
            workspace_repo: params.workspace_repo,
            workspace_member_repo: params.workspace_member_repo,
            workspace_role_repo: params.workspace_role_repo,
        }
    }

    pub async fn handle(
        &self,
        command: RegisterPasswordUserCommand,
    ) -> Result<
        RegisterPasswordUserResult,
        RegisterPasswordUserError<
            U::Error,
            US::Error,
            UIP::Error,
            UEM::Error,
            UEI::Error,
            WR::Error,
            WMR::Error,
            WRR::Error,
        >,
    > {
        // Validate email
        let email = Email::new(&command.email)?;

        // Check if email already exists
        if self
            .user_repo
            .email_exists(&email)
            .await
            .map_err(RegisterPasswordUserError::UserRepository)?
        {
            return Err(RegisterPasswordUserError::EmailAlreadyExists);
        }

        // Validate key lengths
        if command.ecdh_public_key.len() != 32 || command.signing_public_key.len() != 32 {
            return Err(RegisterPasswordUserError::InvalidKeyLength);
        }
        // Salt is 16 bytes per spec
        if command.salt.len() != 16 {
            return Err(RegisterPasswordUserError::InvalidKeyLength);
        }

        // Hash the authKey with bcrypt
        // authKey is base64url encoded, 43 characters (within bcrypt's 72 byte limit)
        let auth_key_hash = bcrypt::hash(&command.auth_key, bcrypt::DEFAULT_COST)
            .map_err(|_| RegisterPasswordUserError::BcryptError)?;

        // Create user
        let user = User::new(email, command.name);

        // Save user
        self.user_repo
            .save(&user)
            .await
            .map_err(RegisterPasswordUserError::UserRepository)?;

        // Create and save default settings
        let settings = UserSettings::new(user.id);
        self.settings_repo
            .save(&settings)
            .await
            .map_err(RegisterPasswordUserError::SettingsRepository)?;

        // Create and save identity public keys
        let public_keys = PublicKeyPair::new(
            command.ecdh_public_key.clone(),
            command.signing_public_key.clone(),
        );
        let identity_public_key = UserIdentityPublicKey::new(user.id, public_keys);
        self.identity_public_key_repo
            .save(&identity_public_key)
            .await
            .map_err(RegisterPasswordUserError::IdentityPublicKeyRepository)?;

        // Create and save encrypted master key
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
        self.encrypted_master_key_repo
            .save(&encrypted_master_key)
            .await
            .map_err(RegisterPasswordUserError::EncryptedMasterKeyRepository)?;

        // Create and save encrypted identity keys
        let encrypted_identity_key = UserEncryptedIdentityKey::new(
            user.id,
            command.encrypted_ecdh_private,
            command.encrypted_ecdh_private_nonce,
            command.encrypted_signing_private,
            command.encrypted_signing_private_nonce,
        );
        self.encrypted_identity_key_repo
            .save(&encrypted_identity_key)
            .await
            .map_err(RegisterPasswordUserError::EncryptedIdentityKeyRepository)?;

        // Create default workspace for the user
        let workspace = self.create_default_workspace(&user).await?;

        Ok(RegisterPasswordUserResult { user, workspace })
    }

    /// Create a default workspace for the newly registered user
    async fn create_default_workspace(
        &self,
        user: &User,
    ) -> Result<
        Workspace,
        RegisterPasswordUserError<
            U::Error,
            US::Error,
            UIP::Error,
            UEM::Error,
            UEI::Error,
            WR::Error,
            WMR::Error,
            WRR::Error,
        >,
    > {
        // Generate slug from user name
        let slug = generate_slug(&user.name)?;

        // Check if slug exists, if so, append a random suffix
        let final_slug = self.ensure_unique_slug(slug).await?;

        // Create default workspace
        let workspace_name = format!("{}'s Workspace", user.name);
        let workspace = Workspace::new(workspace_name, final_slug, user.id);

        // Save workspace
        self.workspace_repo
            .save(&workspace)
            .await
            .map_err(RegisterPasswordUserError::WorkspaceRepository)?;

        // Create owner role
        let owner_role = WorkspaceRole::owner(workspace.id);
        self.workspace_role_repo
            .save(&owner_role)
            .await
            .map_err(RegisterPasswordUserError::WorkspaceRoleRepository)?;

        // Create default roles (editor, viewer)
        let editor_role = WorkspaceRole::editor(workspace.id);
        let viewer_role = WorkspaceRole::viewer(workspace.id);
        self.workspace_role_repo
            .save(&editor_role)
            .await
            .map_err(RegisterPasswordUserError::WorkspaceRoleRepository)?;
        self.workspace_role_repo
            .save(&viewer_role)
            .await
            .map_err(RegisterPasswordUserError::WorkspaceRoleRepository)?;

        // Add user as owner member (and set as default workspace)
        let member = WorkspaceMember::new_owner(workspace.id, user.id, owner_role.id);
        self.workspace_member_repo
            .save(&member)
            .await
            .map_err(RegisterPasswordUserError::WorkspaceMemberRepository)?;

        Ok(workspace)
    }

    async fn ensure_unique_slug(
        &self,
        base_slug: Slug,
    ) -> Result<
        Slug,
        RegisterPasswordUserError<
            U::Error,
            US::Error,
            UIP::Error,
            UEM::Error,
            UEI::Error,
            WR::Error,
            WMR::Error,
            WRR::Error,
        >,
    > {
        let exists = self
            .workspace_repo
            .slug_exists(&base_slug)
            .await
            .map_err(RegisterPasswordUserError::WorkspaceRepository)?;

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
                    .map_err(RegisterPasswordUserError::WorkspaceRepository)?;

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
