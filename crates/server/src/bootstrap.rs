//! Application state bootstrapping
//!
//! Builds repositories, runtime stores, and composes `AppState`.

use infrastructure::PgPool;
use infrastructure::{RedisChallengeStore, RedisRecoveryChallengeStore};
use infrastructure::{RedisPool, RedisTransferNonceStore, RedisTransferStateStore};
use infrastructure::InMemoryChallengeStore;
use infrastructure::InMemoryDeviceEventBus;
use infrastructure::InMemoryWorkspaceEventBus;
use infrastructure::RedisDeviceEventBus;
use infrastructure::RedisWorkspaceEventBus;
use application::types::{ChallengeStore, RecoveryChallengeStore};
use presentation::{AppState, AppStateParams};

use crate::adapters::BoxedRepo;
use std::sync::Arc;

use infrastructure::document::{PgDocumentRepository, PgDocumentUpdateRepository, PgSnapshotRepository};
use infrastructure::encryption::{
    PgDeviceEncryptedUMKRepository, PgDeviceRepository, PgDeviceRevocationEventRepository,
    PgDocumentEncryptedKeyRepository, PgKekRotationCompletionService, PgPendingDeviceRepository,
    PgRotationMarkingService, PgUserEncryptedIdentityKeyRepository,
    PgUserEncryptedMasterKeyRepository, PgUserIdentityPublicKeyRepository,
    PgWorkspaceEncryptedKeyRepository, PgWorkspaceKekBackupRepository,
};
use infrastructure::identity::{PgSessionRepository, PgUserRepository, PgUserSettingsRepository};
use infrastructure::workspace::{
    PgInvitationAcceptanceService, PgInvitationCreationService, PgMemberMutationService,
    PgRoleUpdateService, PgWorkspaceCreationService, PgWorkspaceInvitationRepository,
    PgWorkspaceMemberRepository, PgWorkspaceRepository, PgWorkspaceRolePermissionRepository,
    PgWorkspaceRoleRepository,
};
use infrastructure::PgRegistrationService;

use application::events::DeviceEventBus;
use application::workspace_events::WorkspaceEventBus;

/// Dynamic stores created based on cluster mode (Redis) or single-node (in-memory).
pub type RuntimeStores = (
    Arc<dyn ChallengeStore>,
    Arc<dyn RecoveryChallengeStore>,
    Arc<dyn application::types::TransferNonceStore>,
    Arc<dyn application::types::TransferStateStore>,
    Arc<dyn DeviceEventBus>,
    Arc<dyn WorkspaceEventBus>,
);

/// Compose AppState from all dependencies (DB, Redis/in-memory stores, secrets).
///
/// Builds repositories and runtime stores in one pass — no placeholder values.
pub fn build_app_state(
    pool: Arc<PgPool>,
    redis: &Option<(RedisPool, String)>,
    server_secret: [u8; 32],
) -> AppState {
    let p: PgPool = (*pool).clone();

    // Runtime stores: Redis (cluster) or in-memory (single-node)
    let (challenge_store, recovery_challenge_store, transfer_nonce_store, transfer_state_store, device_event_bus, workspace_event_bus): RuntimeStores =
        if let Some((redis_pool, url)) = redis {
            (
                Arc::new(RedisChallengeStore::new(redis_pool.clone())),
                Arc::new(RedisRecoveryChallengeStore::new(redis_pool.clone())),
                Arc::new(RedisTransferNonceStore::new(redis_pool.clone())),
                Arc::new(RedisTransferStateStore::new(redis_pool.clone())),
                RedisDeviceEventBus::new(redis_pool.clone(), url.clone()),
                RedisWorkspaceEventBus::new(redis_pool.clone(), url.clone()),
            )
        } else {
            (
                Arc::new(InMemoryChallengeStore::default()),
                Arc::new(infrastructure::InMemoryRecoveryChallengeStore::default()),
                Arc::new(infrastructure::InMemoryTransferNonceStore::default()),
                Arc::new(infrastructure::InMemoryTransferStateStore::default()),
                Arc::new(InMemoryDeviceEventBus::new()),
                Arc::new(InMemoryWorkspaceEventBus::new()),
            )
        };

    let secure_cookies = std::env::var("SECURE_COOKIES")
        .map(|v| v.to_lowercase() != "false" && v != "0")
        .unwrap_or(true);
    if !secure_cookies {
        tracing::warn!("SECURE_COOKIES is disabled. This should only be used in development!");
    }

    let params = AppStateParams {
        user_repo: Arc::new(BoxedRepo(PgUserRepository::new(p.clone()))),
        session_repo: Arc::new(BoxedRepo(PgSessionRepository::new(p.clone()))),
        user_settings_repo: Arc::new(BoxedRepo(PgUserSettingsRepository::new(p.clone()))),
        user_identity_public_key_repo: Arc::new(BoxedRepo(PgUserIdentityPublicKeyRepository::new(p.clone()))),
        user_encrypted_master_key_repo: Arc::new(BoxedRepo(PgUserEncryptedMasterKeyRepository::new(p.clone()))),
        user_encrypted_identity_key_repo: Arc::new(BoxedRepo(PgUserEncryptedIdentityKeyRepository::new(p.clone()))),
        workspace_repo: Arc::new(BoxedRepo(PgWorkspaceRepository::new(p.clone()))),
        workspace_member_repo: Arc::new(BoxedRepo(PgWorkspaceMemberRepository::new(p.clone()))),
        workspace_role_repo: Arc::new(BoxedRepo(PgWorkspaceRoleRepository::new(p.clone()))),
        workspace_role_perm_repo: Arc::new(BoxedRepo(PgWorkspaceRolePermissionRepository::new(p.clone()))),
        document_repo: Arc::new(BoxedRepo(PgDocumentRepository::new(p.clone()))),
        document_update_repo: Arc::new(BoxedRepo(PgDocumentUpdateRepository::new(p.clone()))),
        snapshot_repo: Arc::new(BoxedRepo(PgSnapshotRepository::new(p.clone()))),
        workspace_key_repo: Arc::new(BoxedRepo(PgWorkspaceEncryptedKeyRepository::new(p.clone()))),
        document_key_repo: Arc::new(BoxedRepo(PgDocumentEncryptedKeyRepository::new(p.clone()))),
        registration_service: Arc::new(PgRegistrationService::new(Arc::new(p.clone()))),
        device_repo: Arc::new(BoxedRepo(PgDeviceRepository::new(p.clone()))),
        pending_device_repo: Arc::new(BoxedRepo(PgPendingDeviceRepository::new(p.clone()))),
        device_encrypted_umk_repo: Arc::new(BoxedRepo(PgDeviceEncryptedUMKRepository::new(p.clone()))),
        device_revocation_event_repo: Arc::new(BoxedRepo(PgDeviceRevocationEventRepository::new(p.clone()))),
        workspace_kek_backup_repo: Arc::new(BoxedRepo(PgWorkspaceKekBackupRepository::new(p.clone()))),
        workspace_invitation_repo: Arc::new(BoxedRepo(PgWorkspaceInvitationRepository::new(p.clone()))),
        workspace_creation_service: Arc::new(PgWorkspaceCreationService::new(Arc::new(p.clone()))),
        invitation_acceptance_service: Arc::new(PgInvitationAcceptanceService::new(Arc::new(p.clone()))),
        invitation_creation_service: Arc::new(PgInvitationCreationService::new(Arc::new(p.clone()))),
        member_mutation_service: Arc::new(PgMemberMutationService::new(Arc::new(p.clone()))),
        kek_rotation_completion_service: Arc::new(PgKekRotationCompletionService::new(Arc::new(p.clone()))),
        rotation_marking_service: Arc::new(PgRotationMarkingService::new(Arc::new(p.clone()))),
        role_update_service: Arc::new(PgRoleUpdateService::new(p.clone())),
        device_event_bus,
        workspace_event_bus,
        challenge_store,
        recovery_challenge_store,
        transfer_nonce_store,
        transfer_state_store,
        server_secret,
        secure_cookies,
    };

    AppState::new(params)
}
