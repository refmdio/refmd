//! BoxedError repository adapters for the Composition Root
//!
//! Wraps concrete repository implementations and converts their error types
//! to BoxedError for dynamic dispatch via `Arc<dyn Trait<Error = BoxedError>>`.

use application::types::{
    // BoxedError
    BoxedError,
    // ID types
    DocumentId, DocumentSnapshotId, DeviceId, InvitationId, SessionId, UserId, RoleId, WorkspaceId,
    // Entity types
    Document, DocumentSnapshot, DocumentUpdate,
    Device, DeviceEncryptedUMK, DeviceRevocationEvent, DocumentEncryptedKey, PendingDevice,
    UserEncryptedIdentityKey, UserEncryptedMasterKey, UserIdentityPublicKey,
    WorkspaceEncryptedKey, WorkspaceInvitation, WorkspaceKekBackup,
    Email, Session, User, UserSettings,
    Slug, Workspace, WorkspaceMember, WorkspaceRole,
    // Repository traits
    DocumentRepository, DocumentSnapshotRepository, DocumentUpdateRepository,
    DeviceEncryptedUMKRepository, DeviceRepository, DeviceRevocationEventRepository,
    DocumentEncryptedKeyRepository, PendingDeviceRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository,
    WorkspaceEncryptedKeyRepository, WorkspaceInvitationRepository, WorkspaceKekBackupRepository,
    SessionRepository, UserRepository, UserSettingsRepository,
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRolePermission,
    WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
};
use application::types::{SnapshotProof, SnapshotSaveOutcome};
use std::collections::HashMap;

/// Generic adapter that wraps a repository and converts errors to BoxedError
pub struct BoxedRepo<T>(pub T);

fn boxed_err(e: impl std::error::Error + Send + Sync + 'static) -> BoxedError {
    BoxedError::new(e)
}

/// Generates an entire `#[async_trait] impl Trait for BoxedRepo<T>` block.
/// Each method delegates to the inner repository with BoxedError mapping.
macro_rules! impl_boxed_repo {
    (
        $trait_name:ident {
            $(
                fn $method:ident(&self $(, $arg:ident: $arg_ty:ty)*) -> Result<$ret:ty>;
            )*
        }
    ) => {
        #[async_trait::async_trait]
        impl<T: $trait_name + Send + Sync> $trait_name for BoxedRepo<T> {
            type Error = BoxedError;
            $(
                async fn $method(&self, $($arg: $arg_ty),*) -> Result<$ret, Self::Error> {
                    self.0.$method($($arg),*).await.map_err(boxed_err)
                }
            )*
        }
    };
}

// =============================================================================
// Identity
// =============================================================================

impl_boxed_repo!(UserRepository {
    fn find_by_id(&self, id: UserId) -> Result<Option<User>>;
    fn find_by_ids(&self, ids: &[UserId]) -> Result<Vec<User>>;
    fn find_by_email(&self, email: &Email) -> Result<Option<User>>;
    fn email_exists(&self, email: &Email) -> Result<bool>;
    fn save(&self, user: &User) -> Result<()>;
    fn delete(&self, id: UserId) -> Result<()>;
});

impl_boxed_repo!(SessionRepository {
    fn find_by_id(&self, id: SessionId) -> Result<Option<Session>>;
    fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>>;
    fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<Session>>;
    fn save(&self, session: &Session) -> Result<()>;
    fn delete(&self, id: SessionId) -> Result<()>;
    fn delete_by_user_id(&self, user_id: UserId) -> Result<()>;
});

impl_boxed_repo!(UserSettingsRepository {
    fn find_by_user_id(&self, user_id: UserId) -> Result<Option<UserSettings>>;
    fn save(&self, settings: &UserSettings) -> Result<()>;
    fn delete(&self, user_id: UserId) -> Result<()>;
});

// =============================================================================
// Encryption
// =============================================================================

impl_boxed_repo!(DeviceRepository {
    fn find_by_id(&self, id: DeviceId) -> Result<Option<Device>>;
    fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<Device>>;
    fn find_active_by_user_id(&self, user_id: UserId) -> Result<Vec<Device>>;
    fn find_active_by_signing_pub_key(&self, signing_pub_key: &[u8]) -> Result<Option<Device>>;
    fn save(&self, device: &Device) -> Result<()>;
    fn delete(&self, id: DeviceId) -> Result<()>;
});

impl_boxed_repo!(PendingDeviceRepository {
    fn find_by_id(&self, id: DeviceId) -> Result<Option<PendingDevice>>;
    fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<PendingDevice>>;
    fn save(&self, device: &PendingDevice) -> Result<()>;
    fn delete(&self, id: DeviceId) -> Result<()>;
});

impl_boxed_repo!(UserIdentityPublicKeyRepository {
    fn find_by_user_id(&self, user_id: UserId) -> Result<Option<UserIdentityPublicKey>>;
    fn save(&self, key: &UserIdentityPublicKey) -> Result<()>;
    fn delete(&self, user_id: UserId) -> Result<()>;
});

impl_boxed_repo!(UserEncryptedMasterKeyRepository {
    fn find_by_user_id(&self, user_id: UserId) -> Result<Option<UserEncryptedMasterKey>>;
    fn save(&self, key: &UserEncryptedMasterKey) -> Result<()>;
    fn delete(&self, user_id: UserId) -> Result<()>;
});

impl_boxed_repo!(UserEncryptedIdentityKeyRepository {
    fn find_by_user_id(&self, user_id: UserId) -> Result<Option<UserEncryptedIdentityKey>>;
    fn save(&self, key: &UserEncryptedIdentityKey) -> Result<()>;
    fn delete(&self, user_id: UserId) -> Result<()>;
});

impl_boxed_repo!(WorkspaceEncryptedKeyRepository {
    fn find_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<WorkspaceEncryptedKey>>;
    fn find_by_workspace_and_device(&self, workspace_id: WorkspaceId, user_id: UserId, device_id: DeviceId) -> Result<Vec<WorkspaceEncryptedKey>>;
    fn find_active_by_device(&self, workspace_id: WorkspaceId, user_id: UserId, device_id: DeviceId) -> Result<Option<WorkspaceEncryptedKey>>;
    fn save(&self, key: &WorkspaceEncryptedKey) -> Result<()>;
    fn delete_by_workspace_and_user(&self, workspace_id: WorkspaceId, user_id: UserId) -> Result<()>;
});

impl_boxed_repo!(DocumentEncryptedKeyRepository {
    fn find_by_document_id(&self, document_id: DocumentId) -> Result<Vec<DocumentEncryptedKey>>;
    fn find_active_by_document_id(&self, document_id: DocumentId) -> Result<Option<DocumentEncryptedKey>>;
    fn save(&self, key: &DocumentEncryptedKey) -> Result<()>;
    fn delete_by_document_id(&self, document_id: DocumentId) -> Result<()>;
});

impl_boxed_repo!(DeviceRevocationEventRepository {
    fn find_by_user_and_device(&self, user_id: UserId, device_id: DeviceId) -> Result<Option<DeviceRevocationEvent>>;
    fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<DeviceRevocationEvent>>;
    fn save(&self, event: &DeviceRevocationEvent) -> Result<()>;
});

impl_boxed_repo!(WorkspaceKekBackupRepository {
    fn find_active_by_workspace_and_user(&self, workspace_id: WorkspaceId, user_id: UserId) -> Result<Option<WorkspaceKekBackup>>;
    fn save(&self, backup: &WorkspaceKekBackup) -> Result<()>;
    fn find_max_key_version(&self, workspace_id: WorkspaceId) -> Result<Option<i32>>;
});

impl_boxed_repo!(DeviceEncryptedUMKRepository {
    fn find_by_user_and_device(&self, user_id: UserId, device_id: DeviceId) -> Result<Option<DeviceEncryptedUMK>>;
    fn save(&self, umk: &DeviceEncryptedUMK) -> Result<()>;
    fn delete(&self, user_id: UserId, device_id: DeviceId) -> Result<()>;
    fn delete_by_user_id(&self, user_id: UserId) -> Result<()>;
});

// =============================================================================
// Document
// =============================================================================

impl_boxed_repo!(DocumentRepository {
    fn find_by_id(&self, id: DocumentId) -> Result<Option<Document>>;
    fn find_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<Document>>;
    fn find_ids_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<DocumentId>>;
    fn find_by_parent_id(&self, parent_id: DocumentId) -> Result<Vec<Document>>;
    fn find_roots_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<Document>>;
    fn find_needing_dek_rotation(&self, workspace_id: WorkspaceId) -> Result<Vec<Document>>;
    fn slug_exists(&self, workspace_id: WorkspaceId, slug: &str) -> Result<bool>;
    fn save(&self, document: &Document) -> Result<()>;
    fn delete(&self, id: DocumentId) -> Result<()>;
});

// DocumentUpdateRepository needs special handling for is_clock_mismatch
#[async_trait::async_trait]
impl<T: DocumentUpdateRepository + Send + Sync> DocumentUpdateRepository for BoxedRepo<T>
where
    T::Error: 'static,
{
    type Error = BoxedError;

    async fn find_by_snapshot_id(
        &self,
        snapshot_id: DocumentSnapshotId,
        after_version: Option<i64>,
    ) -> Result<Vec<(DocumentUpdate, serde_json::Value)>, Self::Error> {
        self.0
            .find_by_snapshot_id(snapshot_id, after_version)
            .await
            .map_err(boxed_err)
    }

    async fn save_with_clock(
        &self,
        update: &DocumentUpdate,
        snapshot_id: DocumentSnapshotId,
        public_data: serde_json::Value,
    ) -> Result<(i64, i32, i64), Self::Error> {
        self.0
            .save_with_clock(update, snapshot_id, public_data)
            .await
            .map_err(boxed_err)
    }

    fn is_clock_mismatch(&self, err: &Self::Error) -> bool {
        err.downcast_ref::<T::Error>()
            .is_some_and(|inner| self.0.is_clock_mismatch(inner))
    }

    fn is_snapshot_mismatch(&self, err: &Self::Error) -> bool {
        err.downcast_ref::<T::Error>()
            .is_some_and(|inner| self.0.is_snapshot_mismatch(inner))
    }

    fn is_key_version_too_old(&self, err: &Self::Error) -> bool {
        err.downcast_ref::<T::Error>()
            .is_some_and(|inner| self.0.is_key_version_too_old(inner))
    }

    async fn find_by_snapshot_id_after_clocks(
        &self,
        snapshot_id: DocumentSnapshotId,
        known_clocks: &HashMap<String, i64>,
    ) -> Result<Vec<(DocumentUpdate, serde_json::Value)>, Self::Error> {
        self.0
            .find_by_snapshot_id_after_clocks(snapshot_id, known_clocks)
            .await
            .map_err(boxed_err)
    }

    async fn delete_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<(), Self::Error> {
        self.0
            .delete_by_document_id(document_id)
            .await
            .map_err(boxed_err)
    }
}

// DocumentSnapshotRepository
#[async_trait::async_trait]
impl<T: DocumentSnapshotRepository + Send + Sync> DocumentSnapshotRepository for BoxedRepo<T>
where
    T::Error: 'static,
{
    type Error = BoxedError;

    async fn find_active_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Option<(DocumentSnapshot, serde_json::Value)>, Self::Error> {
        self.0
            .find_active_by_document_id(document_id)
            .await
            .map_err(boxed_err)
    }

    async fn find_by_id(
        &self,
        id: DocumentSnapshotId,
    ) -> Result<Option<(DocumentSnapshot, serde_json::Value)>, Self::Error> {
        self.0.find_by_id(id).await.map_err(boxed_err)
    }

    async fn save(
        &self,
        snapshot: &DocumentSnapshot,
        expected_parent_id: Option<DocumentSnapshotId>,
        expected_parent_clocks: &std::collections::HashMap<String, i64>,
        public_data: serde_json::Value,
    ) -> Result<SnapshotSaveOutcome, Self::Error> {
        self.0
            .save(snapshot, expected_parent_id, expected_parent_clocks, public_data)
            .await
            .map_err(boxed_err)
    }

    async fn find_proof_chain(
        &self,
        document_id: DocumentId,
        from_snapshot_id: DocumentSnapshotId,
        up_to_snapshot_id: DocumentSnapshotId,
    ) -> Result<Vec<SnapshotProof>, Self::Error> {
        self.0
            .find_proof_chain(document_id, from_snapshot_id, up_to_snapshot_id)
            .await
            .map_err(boxed_err)
    }

    async fn get_snapshot_clocks(
        &self,
        snapshot_id: DocumentSnapshotId,
    ) -> Result<HashMap<String, i64>, Self::Error> {
        self.0
            .get_snapshot_clocks(snapshot_id)
            .await
            .map_err(boxed_err)
    }

}

// =============================================================================
// Workspace
// =============================================================================

// WorkspaceRepository needs special handling to capture classifier flags
#[async_trait::async_trait]
impl<T: WorkspaceRepository + Send + Sync> WorkspaceRepository for BoxedRepo<T>
where
    T::Error: 'static,
{
    type Error = BoxedError;

    async fn find_by_id(&self, id: WorkspaceId) -> Result<Option<Workspace>, Self::Error> {
        self.0.find_by_id(id).await.map_err(BoxedError::from_workspace_repo)
    }
    async fn find_by_slug(&self, slug: &Slug) -> Result<Option<Workspace>, Self::Error> {
        self.0.find_by_slug(slug).await.map_err(BoxedError::from_workspace_repo)
    }
    async fn find_by_ids(&self, ids: &[WorkspaceId]) -> Result<Vec<Workspace>, Self::Error> {
        self.0.find_by_ids(ids).await.map_err(BoxedError::from_workspace_repo)
    }
    async fn slug_exists(&self, slug: &Slug) -> Result<bool, Self::Error> {
        self.0.slug_exists(slug).await.map_err(BoxedError::from_workspace_repo)
    }
    async fn save(&self, workspace: &Workspace) -> Result<(), Self::Error> {
        self.0.save(workspace).await.map_err(BoxedError::from_workspace_repo)
    }
    async fn update(&self, workspace: &Workspace) -> Result<bool, Self::Error> {
        self.0.update(workspace).await.map_err(BoxedError::from_workspace_repo)
    }
    async fn delete(&self, id: WorkspaceId) -> Result<(), Self::Error> {
        self.0.delete(id).await.map_err(BoxedError::from_workspace_repo)
    }
}

impl_boxed_repo!(WorkspaceMemberRepository {
    fn find_by_workspace_and_user(&self, workspace_id: WorkspaceId, user_id: UserId) -> Result<Option<WorkspaceMember>>;
    fn find_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<WorkspaceMember>>;
    fn find_by_user_id(&self, user_id: UserId) -> Result<Vec<WorkspaceMember>>;
    fn find_default_by_user_id(&self, user_id: UserId) -> Result<Option<WorkspaceMember>>;
    fn save(&self, member: &WorkspaceMember) -> Result<()>;
    fn delete(&self, workspace_id: WorkspaceId, user_id: UserId) -> Result<()>;
    fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<()>;
    fn clear_default_for_user(&self, user_id: UserId) -> Result<()>;
});

// WorkspaceRoleRepository needs special handling to capture classifier flags
#[async_trait::async_trait]
impl<T: WorkspaceRoleRepository + Send + Sync> WorkspaceRoleRepository for BoxedRepo<T>
where
    T::Error: 'static,
{
    type Error = BoxedError;

    async fn find_by_id(&self, id: RoleId) -> Result<Option<WorkspaceRole>, Self::Error> {
        self.0.find_by_id(id).await.map_err(BoxedError::from_role_repo)
    }
    async fn find_by_ids(&self, ids: &[RoleId]) -> Result<Vec<WorkspaceRole>, Self::Error> {
        self.0.find_by_ids(ids).await.map_err(BoxedError::from_role_repo)
    }
    async fn find_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<WorkspaceRole>, Self::Error> {
        self.0.find_by_workspace_id(workspace_id).await.map_err(BoxedError::from_role_repo)
    }
    async fn save(&self, role: &WorkspaceRole) -> Result<(), Self::Error> {
        self.0.save(role).await.map_err(BoxedError::from_role_repo)
    }
    async fn update(&self, role: &WorkspaceRole) -> Result<bool, Self::Error> {
        self.0.update(role).await.map_err(BoxedError::from_role_repo)
    }
    async fn delete(&self, id: RoleId, workspace_id: WorkspaceId) -> Result<(), Self::Error> {
        self.0.delete(id, workspace_id).await.map_err(BoxedError::from_role_repo)
    }
    async fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<(), Self::Error> {
        self.0.delete_by_workspace_id(workspace_id).await.map_err(BoxedError::from_role_repo)
    }
    async fn swap_default(&self, workspace_id: WorkspaceId, new_default_role_id: RoleId, new_name: Option<&str>) -> Result<(), Self::Error> {
        self.0.swap_default(workspace_id, new_default_role_id, new_name).await.map_err(BoxedError::from_role_repo)
    }
    async fn save_and_set_default(&self, role: &WorkspaceRole) -> Result<(), Self::Error> {
        self.0.save_and_set_default(role).await.map_err(BoxedError::from_role_repo)
    }
}

impl_boxed_repo!(WorkspaceRolePermissionRepository {
    fn find_by_role_id(&self, role_id: RoleId) -> Result<Vec<WorkspaceRolePermission>>;
    fn find_by_role_ids(&self, role_ids: &[RoleId]) -> Result<Vec<WorkspaceRolePermission>>;
    fn save_batch(&self, role_id: RoleId, perms: &[(String, bool)]) -> Result<()>;
    fn delete_by_role_id(&self, role_id: RoleId) -> Result<()>;
});

impl_boxed_repo!(WorkspaceInvitationRepository {
    fn find_by_id(&self, id: InvitationId) -> Result<Option<WorkspaceInvitation>>;
    fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<WorkspaceInvitation>>;
    fn find_active_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<WorkspaceInvitation>>;
    fn save(&self, invitation: &WorkspaceInvitation) -> Result<()>;
    fn revoke(&self, id: InvitationId, workspace_id: WorkspaceId) -> Result<bool>;
    fn count_by_role_id(&self, workspace_id: WorkspaceId, role_id: RoleId) -> Result<i64>;
    fn revoke_all_active(&self, workspace_id: WorkspaceId) -> Result<i64>;
});
