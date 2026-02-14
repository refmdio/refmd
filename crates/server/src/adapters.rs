//! BoxedError repository adapters for the Composition Root
//!
//! Wraps concrete repository implementations and converts their error types
//! to BoxedError for dynamic dispatch via `Arc<dyn Trait<Error = BoxedError>>`.

use application::types::{
    // BoxedError
    BoxedError,
    // ID types
    DocumentId, DeviceId, SessionId, UserId, RoleId, WorkspaceId,
    // Entity types
    Document, DocumentUpdate,
    Device, DeviceEncryptedUMK, DeviceRevocationEvent, DocumentEncryptedKey, PendingDevice,
    UserEncryptedIdentityKey, UserEncryptedMasterKey, UserIdentityPublicKey,
    WorkspaceEncryptedKey, WorkspaceKekBackup,
    Email, Session, User, UserSettings,
    Slug, Workspace, WorkspaceMember, WorkspaceRole,
    // Repository traits
    DocumentRepository, DocumentUpdateRepository,
    DeviceEncryptedUMKRepository, DeviceRepository, DeviceRevocationEventRepository,
    DocumentEncryptedKeyRepository, PendingDeviceRepository, UserEncryptedIdentityKeyRepository,
    UserEncryptedMasterKeyRepository, UserIdentityPublicKeyRepository,
    WorkspaceEncryptedKeyRepository, WorkspaceKekBackupRepository,
    SessionRepository, UserRepository, UserSettingsRepository,
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRoleRepository,
};

/// Generic adapter that wraps a repository and converts errors to BoxedError
pub struct BoxedRepo<T>(pub T);

fn boxed_err(e: impl std::error::Error + Send + Sync + 'static) -> BoxedError {
    BoxedError(Box::new(e))
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
    fn find_by_parent_id(&self, parent_id: DocumentId) -> Result<Vec<Document>>;
    fn find_roots_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<Document>>;
    fn find_needing_dek_rotation(&self, workspace_id: WorkspaceId) -> Result<Vec<Document>>;
    fn slug_exists(&self, workspace_id: WorkspaceId, slug: &str) -> Result<bool>;
    fn save(&self, document: &Document) -> Result<()>;
    fn delete(&self, id: DocumentId) -> Result<()>;
});

// DocumentUpdateRepository needs special handling for is_duplicate_hash/is_chain_mismatch
#[async_trait::async_trait]
impl<T: DocumentUpdateRepository + Send + Sync> DocumentUpdateRepository for BoxedRepo<T>
where
    T::Error: 'static,
{
    type Error = BoxedError;

    async fn find_by_document_id(
        &self,
        document_id: DocumentId,
    ) -> Result<Vec<DocumentUpdate>, Self::Error> {
        self.0
            .find_by_document_id(document_id)
            .await
            .map_err(boxed_err)
    }

    async fn find_by_document_id_after_seq(
        &self,
        document_id: DocumentId,
        after_seq: i64,
    ) -> Result<Vec<DocumentUpdate>, Self::Error> {
        self.0
            .find_by_document_id_after_seq(document_id, after_seq)
            .await
            .map_err(boxed_err)
    }

    async fn find_by_hash(
        &self,
        update_hash: &str,
    ) -> Result<Option<DocumentUpdate>, Self::Error> {
        self.0.find_by_hash(update_hash).await.map_err(boxed_err)
    }

    async fn get_latest_seq(
        &self,
        document_id: DocumentId,
    ) -> Result<Option<i64>, Self::Error> {
        self.0
            .get_latest_seq(document_id)
            .await
            .map_err(boxed_err)
    }

    async fn get_latest_update_hash(
        &self,
        document_id: DocumentId,
    ) -> Result<Option<String>, Self::Error> {
        self.0
            .get_latest_update_hash(document_id)
            .await
            .map_err(boxed_err)
    }

    async fn save(
        &self,
        update: &DocumentUpdate,
    ) -> Result<(i64, i64), Self::Error> {
        self.0.save(update).await.map_err(boxed_err)
    }

    fn is_duplicate_hash(&self, err: &Self::Error) -> bool {
        err.0
            .downcast_ref::<T::Error>()
            .is_some_and(|inner| self.0.is_duplicate_hash(inner))
    }

    fn is_chain_mismatch(&self, err: &Self::Error) -> bool {
        err.0
            .downcast_ref::<T::Error>()
            .is_some_and(|inner| self.0.is_chain_mismatch(inner))
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

    async fn delete_before_seq(
        &self,
        document_id: DocumentId,
        before_seq: i64,
    ) -> Result<u64, Self::Error> {
        self.0
            .delete_before_seq(document_id, before_seq)
            .await
            .map_err(boxed_err)
    }
}

// =============================================================================
// Workspace
// =============================================================================

impl_boxed_repo!(WorkspaceRepository {
    fn find_by_id(&self, id: WorkspaceId) -> Result<Option<Workspace>>;
    fn find_by_slug(&self, slug: &Slug) -> Result<Option<Workspace>>;
    fn find_by_ids(&self, ids: &[WorkspaceId]) -> Result<Vec<Workspace>>;
    fn slug_exists(&self, slug: &Slug) -> Result<bool>;
    fn save(&self, workspace: &Workspace) -> Result<()>;
    fn delete(&self, id: WorkspaceId) -> Result<()>;
});

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

impl_boxed_repo!(WorkspaceRoleRepository {
    fn find_by_id(&self, id: RoleId) -> Result<Option<WorkspaceRole>>;
    fn find_by_ids(&self, ids: &[RoleId]) -> Result<Vec<WorkspaceRole>>;
    fn find_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<Vec<WorkspaceRole>>;
    fn save(&self, role: &WorkspaceRole) -> Result<()>;
    fn delete(&self, id: RoleId) -> Result<()>;
    fn delete_by_workspace_id(&self, workspace_id: WorkspaceId) -> Result<()>;
});
