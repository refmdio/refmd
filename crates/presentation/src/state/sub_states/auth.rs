use std::sync::Arc;

use super::*;

/// Sub-state for auth-related routes (login, register, salt, session, recovery, pop-challenge)
#[derive(Clone)]
pub struct AuthSubState {
    pub user_repo: DynUserRepository,
    pub session_repo: DynSessionRepository,
    pub user_settings_repo: DynUserSettingsRepository,
    pub user_identity_public_key_repo: DynUserIdentityPublicKeyRepository,
    pub user_encrypted_master_key_repo: DynUserEncryptedMasterKeyRepository,
    pub user_encrypted_identity_key_repo: DynUserEncryptedIdentityKeyRepository,
    pub device_repo: DynDeviceRepository,
    pub workspace_repo: DynWorkspaceRepository,
    pub registration_service: DynRegistrationService,
    pub challenge_store: DynChallengeStore,
    pub recovery_challenge_store: DynRecoveryChallengeStore,
    pub server_secret: Arc<[u8; 32]>,
    pub secure_cookies: bool,
}

impl_from_ref!(AuthSubState {
    user_repo, session_repo, user_settings_repo,
    user_identity_public_key_repo, user_encrypted_master_key_repo,
    user_encrypted_identity_key_repo, device_repo, workspace_repo,
    registration_service, challenge_store, recovery_challenge_store,
    server_secret,
    secure_cookies @Clone::clone,
});
