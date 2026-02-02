//! Register password user command
//!
//! Complete registration for password-based users including all encryption keys.

use std::sync::Arc;
use domain::encryption::{
    KdfParams, PublicKeyPair, UserEncryptedIdentityKey, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKey, UserEncryptedMasterKeyRepository, UserIdentityPublicKey,
    UserIdentityPublicKeyRepository,
};
use domain::identity::{
    Email, EmailError, User, UserRepository, UserSettings, UserSettingsRepository,
};
use thiserror::Error;

/// Register password user command
#[derive(Debug)]
pub struct RegisterPasswordUserCommand {
    // Basic info
    pub email: String,
    pub name: String,

    // authKey for login (will be bcrypt hashed on server)
    pub auth_key: String,

    // Salt for KDF (client-generated, 32 bytes base64)
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
}

/// Register password user error
#[derive(Debug, Error)]
pub enum RegisterPasswordUserError<
    UR: std::error::Error,
    US: std::error::Error,
    UIP: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
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
}

impl<UR, US, UIP, UEM, UEI> RegisterPasswordUserError<UR, US, UIP, UEM, UEI>
where
    UR: std::error::Error,
    US: std::error::Error,
    UIP: std::error::Error,
    UEM: std::error::Error,
    UEI: std::error::Error,
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

/// Register password user handler
pub struct RegisterPasswordUserHandler<U, US, UIP, UEM, UEI> {
    user_repo: Arc<U>,
    settings_repo: Arc<US>,
    identity_public_key_repo: Arc<UIP>,
    encrypted_master_key_repo: Arc<UEM>,
    encrypted_identity_key_repo: Arc<UEI>,
}

impl<U, US, UIP, UEM, UEI> RegisterPasswordUserHandler<U, US, UIP, UEM, UEI>
where
    U: UserRepository,
    US: UserSettingsRepository,
    UIP: UserIdentityPublicKeyRepository,
    UEM: UserEncryptedMasterKeyRepository,
    UEI: UserEncryptedIdentityKeyRepository,
{
    pub fn new(
        user_repo: Arc<U>,
        settings_repo: Arc<US>,
        identity_public_key_repo: Arc<UIP>,
        encrypted_master_key_repo: Arc<UEM>,
        encrypted_identity_key_repo: Arc<UEI>,
    ) -> Self {
        Self {
            user_repo,
            settings_repo,
            identity_public_key_repo,
            encrypted_master_key_repo,
            encrypted_identity_key_repo,
        }
    }

    pub async fn handle(
        &self,
        command: RegisterPasswordUserCommand,
    ) -> Result<
        RegisterPasswordUserResult,
        RegisterPasswordUserError<U::Error, US::Error, UIP::Error, UEM::Error, UEI::Error>,
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
        if command.salt.len() != 32 {
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

        Ok(RegisterPasswordUserResult { user })
    }
}
