use application::types::{
    BoxedError, DeviceRepository, DocumentRepository, DocumentUpdateRepository,
    WorkspaceMemberRepository, WorkspaceRolePermissionRepository, WorkspaceRoleRepository,
};
use std::sync::Arc;

use super::*;

// Handler type aliases (clippy::type_complexity)
type DynCreateUpdateHandler = application::document::CreateDocumentUpdateHandler<
    dyn DocumentRepository<Error = BoxedError>,
    dyn DocumentUpdateRepository<Error = BoxedError>,
    dyn WorkspaceMemberRepository<Error = BoxedError>,
    dyn WorkspaceRoleRepository<Error = BoxedError>,
    dyn WorkspaceRolePermissionRepository<Error = BoxedError>,
    dyn DeviceRepository<Error = BoxedError>,
>;

type DynListUpdatesHandler = application::document::ListDocumentUpdatesHandler<
    dyn DocumentRepository<Error = BoxedError>,
    dyn DocumentUpdateRepository<Error = BoxedError>,
    dyn WorkspaceMemberRepository<Error = BoxedError>,
    dyn WorkspaceRoleRepository<Error = BoxedError>,
    dyn WorkspaceRolePermissionRepository<Error = BoxedError>,
>;

/// Sub-state for document-related routes
#[derive(Clone)]
pub struct DocumentSubState {
    pub document_repo: DynDocumentRepository,
    pub document_update_repo: DynDocumentUpdateRepository,
    pub document_key_repo: DynDocumentEncryptedKeyRepository,
    pub workspace_member_repo: DynWorkspaceMemberRepository,
    pub workspace_role_repo: DynWorkspaceRoleRepository,
    pub workspace_role_perm_repo: DynWorkspaceRolePermissionRepository,
    pub device_repo: DynDeviceRepository,
}

impl DocumentSubState {
    /// Clone the repos needed by most document CRUD handlers.
    pub fn doc_member_role_repos(
        &self,
    ) -> (
        DynDocumentRepository,
        DynWorkspaceMemberRepository,
        DynWorkspaceRoleRepository,
        DynWorkspaceRolePermissionRepository,
    ) {
        (
            self.document_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
        )
    }

    pub fn list_updates_handler(&self) -> DynListUpdatesHandler {
        application::document::ListDocumentUpdatesHandler::new(
            self.document_repo.clone(),
            self.document_update_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
        )
    }

    pub fn create_update_handler(&self) -> DynCreateUpdateHandler {
        application::document::CreateDocumentUpdateHandler::new(
            self.document_repo.clone(),
            self.document_update_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
            self.device_repo.clone(),
        )
    }
}

impl_from_ref!(DocumentSubState {
    document_repo, document_update_repo, document_key_repo,
    workspace_member_repo, workspace_role_repo, workspace_role_perm_repo, device_repo,
});
