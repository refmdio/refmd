//! Workspace event → document disconnect service
//!
//! Encapsulates the business logic for disconnecting users from document
//! WebSocket connections when workspace membership changes occur.
//! Keeps this orchestration in the application layer rather than presentation.

use crate::types::{DocumentId, UserId};
use domain::document::DocumentRepository;
use domain::WorkspaceEvent;
use std::sync::Arc;

/// Trait for managing document WebSocket connections.
/// Implemented by the presentation layer's connection store.
pub trait DocumentConnectionManager: Send + Sync {
    /// Disconnect a user from specific documents
    fn disconnect_user_from_documents(&self, user_id: UserId, document_ids: &[DocumentId]);
}

/// Handles workspace events that require WebSocket disconnection
pub struct WorkspaceDisconnectService<DR: ?Sized> {
    document_repo: Arc<DR>,
}

impl<DR: ?Sized + DocumentRepository> WorkspaceDisconnectService<DR> {
    pub fn new(document_repo: Arc<DR>) -> Self {
        Self { document_repo }
    }

    /// Process a workspace event and disconnect affected users
    pub async fn handle_event(
        &self,
        event: &WorkspaceEvent,
        manager: &dyn DocumentConnectionManager,
    ) {
        match event {
            WorkspaceEvent::MemberRemoved {
                workspace_id,
                removed_user_id,
            } => {
                self.disconnect_from_workspace(*workspace_id, *removed_user_id, manager)
                    .await;
            }
            WorkspaceEvent::MemberRoleChanged {
                workspace_id,
                target_user_id,
            } => {
                self.disconnect_from_workspace(*workspace_id, *target_user_id, manager)
                    .await;
            }
            _ => {}
        }
    }

    async fn disconnect_from_workspace(
        &self,
        workspace_id: domain::workspace::WorkspaceId,
        user_id: UserId,
        manager: &dyn DocumentConnectionManager,
    ) {
        match self
            .document_repo
            .find_ids_by_workspace_id(workspace_id)
            .await
        {
            Ok(doc_ids) => {
                manager.disconnect_user_from_documents(user_id, &doc_ids);
            }
            Err(e) => {
                // Transient DB failure: log and skip rather than escalating to
                // global disconnect (which would disrupt unrelated workspaces).
                // The lazy RBAC check at broadcast time will catch any truly
                // unauthorized connections on the next message.
                tracing::warn!(
                    "Failed to list workspace documents for scoped disconnect, skipping (lazy RBAC will catch): {e}"
                );
            }
        }
    }
}
