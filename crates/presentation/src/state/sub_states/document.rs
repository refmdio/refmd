use application::types::{
    BoxedError, DeviceRepository, DocumentRepository, DocumentSnapshotRepository,
    DocumentUpdateRepository, WorkspaceMemberRepository, WorkspaceRolePermissionRepository,
    WorkspaceRoleRepository,
};
use std::sync::Arc;

use super::*;

// Handler type aliases (clippy::type_complexity)
type DynCreateUpdateHandler = application::document::CreateDocumentUpdateHandler<
    dyn DocumentRepository<Error = BoxedError>,
    dyn DocumentUpdateRepository<Error = BoxedError>,
    dyn DocumentSnapshotRepository<Error = BoxedError>,
    dyn WorkspaceMemberRepository<Error = BoxedError>,
    dyn WorkspaceRoleRepository<Error = BoxedError>,
    dyn WorkspaceRolePermissionRepository<Error = BoxedError>,
    dyn DeviceRepository<Error = BoxedError>,
>;

type DynCreateSnapshotHandler = application::document::CreateSnapshotHandler<
    dyn DocumentRepository<Error = BoxedError>,
    dyn DocumentSnapshotRepository<Error = BoxedError>,
    dyn WorkspaceMemberRepository<Error = BoxedError>,
    dyn WorkspaceRoleRepository<Error = BoxedError>,
    dyn WorkspaceRolePermissionRepository<Error = BoxedError>,
    dyn DeviceRepository<Error = BoxedError>,
>;

type DynFetchDocumentSnapshotHandler =
    application::document::FetchDocumentSnapshotHandler<
        dyn DocumentRepository<Error = BoxedError>,
        dyn DocumentSnapshotRepository<Error = BoxedError>,
        dyn DocumentUpdateRepository<Error = BoxedError>,
    >;

/// Sub-state for document-related routes
#[derive(Clone)]
pub struct DocumentSubState {
    pub document_repo: DynDocumentRepository,
    pub document_update_repo: DynDocumentUpdateRepository,
    pub snapshot_repo: DynSnapshotRepository,
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

    pub fn create_update_handler(&self) -> DynCreateUpdateHandler {
        application::document::CreateDocumentUpdateHandler::new(
            self.document_repo.clone(),
            self.document_update_repo.clone(),
            self.snapshot_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
            self.device_repo.clone(),
        )
    }

    pub fn create_snapshot_handler(&self) -> DynCreateSnapshotHandler {
        application::document::CreateSnapshotHandler::new(
            self.document_repo.clone(),
            self.snapshot_repo.clone(),
            self.workspace_member_repo.clone(),
            self.workspace_role_repo.clone(),
            self.workspace_role_perm_repo.clone(),
            self.device_repo.clone(),
        )
    }

    pub fn fetch_document_snapshot_handler(&self) -> DynFetchDocumentSnapshotHandler {
        application::document::FetchDocumentSnapshotHandler::new(
            self.document_repo.clone(),
            self.snapshot_repo.clone(),
            self.document_update_repo.clone(),
        )
    }
}

impl_from_ref!(DocumentSubState {
    document_repo, document_update_repo, snapshot_repo, document_key_repo,
    workspace_member_repo, workspace_role_repo, workspace_role_perm_repo, device_repo,
});
