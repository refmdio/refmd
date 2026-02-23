use application::types::{
    BoxedError as BE, DeviceRepository,
    DocumentEncryptedKeyRepository as DocKeyRepo, DocumentRepository,
    WorkspaceEncryptedKeyRepository as WsKeyRepo,
    WorkspaceKekBackupRepository as WsKekBackupRepo,
    WorkspaceMemberRepository, WorkspaceRepository, WorkspaceRolePermissionRepository,
    WorkspaceRoleRepository,
};
use std::sync::Arc;

use super::*;

// Handler type aliases to satisfy clippy::type_complexity
type DynSaveWorkspaceKeyHandler = application::encryption::SaveWorkspaceKeyHandler<
    dyn WsKeyRepo<Error = BE>,
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn DeviceRepository<Error = BE>,
    dyn WorkspaceRepository<Error = BE>,
>;

type DynGetWorkspaceKeyHandler = application::encryption::GetWorkspaceKeyHandler<
    dyn WsKeyRepo<Error = BE>,
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn DeviceRepository<Error = BE>,
>;

type DynSaveDocumentKeyHandler = application::encryption::SaveDocumentKeyHandler<
    dyn DocKeyRepo<Error = BE>,
    dyn DocumentRepository<Error = BE>,
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
>;

type DynGetDocumentKeyHandler = application::encryption::GetDocumentKeyHandler<
    dyn DocKeyRepo<Error = BE>,
    dyn DocumentRepository<Error = BE>,
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WorkspaceRoleRepository<Error = BE>,
    dyn WorkspaceRolePermissionRepository<Error = BE>,
>;

type DynSaveWorkspaceKekBackupHandler = application::encryption::SaveWorkspaceKekBackupHandler<
    dyn WsKekBackupRepo<Error = BE>,
    dyn WorkspaceMemberRepository<Error = BE>,
    dyn WsKeyRepo<Error = BE>,
>;

type DynCompleteKekRotationHandler = application::encryption::CompleteKekRotationHandler<
    dyn WorkspaceMemberRepository<Error = BE>,
>;

/// Sub-state for encryption/key-related routes
#[derive(Clone)]
pub struct EncryptionSubState {
    pub workspace_key_repo: DynWorkspaceEncryptedKeyRepository,
    pub document_key_repo: DynDocumentEncryptedKeyRepository,
    pub workspace_kek_backup_repo: DynWorkspaceKekBackupRepository,
    pub device_repo: DynDeviceRepository,
    pub workspace_member_repo: DynWorkspaceMemberRepository,
    pub workspace_role_repo: DynWorkspaceRoleRepository,
    pub workspace_role_perm_repo: DynWorkspaceRolePermissionRepository,
    pub workspace_repo: DynWorkspaceRepository,
    pub document_repo: DynDocumentRepository,
    pub kek_rotation_completion_service: DynKekRotationCompletionService,
}

impl EncryptionSubState {
    pub fn save_document_key_handler(&self) -> DynSaveDocumentKeyHandler {
        application::encryption::SaveDocumentKeyHandler::new(
            self.document_key_repo.clone(),
            self.document_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
        )
    }

    pub fn get_document_key_handler(&self) -> DynGetDocumentKeyHandler {
        application::encryption::GetDocumentKeyHandler::new(
            self.document_key_repo.clone(),
            self.document_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
        )
    }

    pub fn save_workspace_key_handler(&self) -> DynSaveWorkspaceKeyHandler {
        application::encryption::SaveWorkspaceKeyHandler::new(
            self.workspace_key_repo.clone(),
            self.workspace_member_repo.clone(),
            self.device_repo.clone(),
            self.workspace_repo.clone(),
        )
    }

    pub fn get_workspace_key_handler(&self) -> DynGetWorkspaceKeyHandler {
        application::encryption::GetWorkspaceKeyHandler::new(
            self.workspace_key_repo.clone(),
            self.workspace_member_repo.clone(),
            self.device_repo.clone(),
        )
    }

    pub fn complete_kek_rotation_handler(&self) -> DynCompleteKekRotationHandler {
        application::encryption::CompleteKekRotationHandler::new(
            self.workspace_member_repo.clone(),
            self.kek_rotation_completion_service.clone(),
        )
    }

    pub fn save_workspace_kek_backup_handler(&self) -> DynSaveWorkspaceKekBackupHandler {
        application::encryption::SaveWorkspaceKekBackupHandler::new(
            self.workspace_kek_backup_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_key_repo.clone(),
        )
    }

    pub fn get_workspace_kek_backup_handler(
        &self,
    ) -> application::encryption::GetWorkspaceKekBackupHandler<
        dyn WsKekBackupRepo<Error = BE>,
        dyn WorkspaceMemberRepository<Error = BE>,
    > {
        application::encryption::GetWorkspaceKekBackupHandler::new(
            self.workspace_kek_backup_repo.clone(),
            self.workspace_member_repo.clone(),
        )
    }
}

impl_from_ref!(EncryptionSubState {
    workspace_key_repo, document_key_repo, workspace_kek_backup_repo,
    device_repo, workspace_member_repo, workspace_role_repo, workspace_role_perm_repo,
    workspace_repo, document_repo, kek_rotation_completion_service,
});
