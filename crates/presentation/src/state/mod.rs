//! Application state with dynamic dispatch for dependency injection

mod sub_states;
pub(crate) mod type_aliases;

pub use sub_states::{
    AuthSubState, DeviceSubState, DocumentSubState, EncryptionSubState, TrustTransferSubState,
    WorkspaceSubState,
};
use type_aliases::*;

use std::sync::Arc;

// =============================================================================
// Macro to eliminate the 3x field repetition (Params / State / new)
// =============================================================================

/// Define AppStateParams, AppState, and AppState::new() with one field list.
///
/// `arc` fields are `Arc<dyn Trait>` and simply moved from params to state.
/// `wrap` fields have a params type that is converted in `new()`.
macro_rules! define_state {
    (
        arc: [ $( $af:ident : $at:ty ),+ $(,)? ],
        wrap: [ $( $wf:ident { params: $wpt:ty, state: $wst:ty, conv: $wconv:expr } ),* $(,)? ]
    ) => {
        /// Parameters for creating AppState
        pub struct AppStateParams {
            $( pub $af: $at, )+
            $( pub $wf: $wpt, )*
        }

        /// Application state holding repository implementations via dynamic dispatch
        #[derive(Clone)]
        pub struct AppState {
            $( $af: $at, )+
            $( $wf: $wst, )*
        }

        impl AppState {
            pub fn new(params: AppStateParams) -> Self {
                Self {
                    $( $af: params.$af, )+
                    $( $wf: ($wconv)(params.$wf), )*
                }
            }
        }
    };
}

define_state! {
    arc: [
        user_repo: DynUserRepository,
        session_repo: DynSessionRepository,
        user_settings_repo: DynUserSettingsRepository,
        user_identity_public_key_repo: DynUserIdentityPublicKeyRepository,
        user_encrypted_master_key_repo: DynUserEncryptedMasterKeyRepository,
        user_encrypted_identity_key_repo: DynUserEncryptedIdentityKeyRepository,
        workspace_repo: DynWorkspaceRepository,
        workspace_member_repo: DynWorkspaceMemberRepository,
        workspace_role_repo: DynWorkspaceRoleRepository,
        workspace_role_perm_repo: DynWorkspaceRolePermissionRepository,
        document_repo: DynDocumentRepository,
        document_update_repo: DynDocumentUpdateRepository,
        workspace_key_repo: DynWorkspaceEncryptedKeyRepository,
        document_key_repo: DynDocumentEncryptedKeyRepository,
        registration_service: DynRegistrationService,
        device_repo: DynDeviceRepository,
        pending_device_repo: DynPendingDeviceRepository,
        device_encrypted_umk_repo: DynDeviceEncryptedUMKRepository,
        device_revocation_event_repo: DynDeviceRevocationEventRepository,
        workspace_kek_backup_repo: DynWorkspaceKekBackupRepository,
        workspace_invitation_repo: DynWorkspaceInvitationRepository,
        workspace_creation_service: DynWorkspaceCreationService,
        invitation_acceptance_service: DynInvitationAcceptanceService,
        invitation_creation_service: DynInvitationCreationService,
        member_mutation_service: DynMemberMutationService,
        kek_rotation_completion_service: DynKekRotationCompletionService,
        rotation_marking_service: DynRotationMarkingService,
        role_update_service: DynRoleUpdateService,
        device_event_bus: DynDeviceEventBus,
        workspace_event_bus: DynWorkspaceEventBus,
        challenge_store: DynChallengeStore,
        recovery_challenge_store: DynRecoveryChallengeStore,
        transfer_nonce_store: DynTransferNonceStore,
        transfer_state_store: DynTransferStateStore,
    ],
    wrap: [
        server_secret { params: [u8; 32], state: Arc<[u8; 32]>, conv: Arc::new },
        secure_cookies { params: bool, state: bool, conv: std::convert::identity },
    ]
}

impl AppState {
    pub fn session_repo(&self) -> DynSessionRepository {
        Arc::clone(&self.session_repo)
    }

    pub fn device_repo(&self) -> DynDeviceRepository {
        Arc::clone(&self.device_repo)
    }

    pub fn challenge_store(&self) -> DynChallengeStore {
        Arc::clone(&self.challenge_store)
    }
}
