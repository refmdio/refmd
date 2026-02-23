//! In-memory workspace event bus for single-node deployments

use application::workspace_events::{WorkspaceEventPublisher, WorkspaceEventSubscriber};
use async_trait::async_trait;
use domain::WorkspaceEvent;
use tokio::sync::broadcast;

/// In-memory event bus for single-node deployments
#[derive(Clone)]
pub struct InMemoryWorkspaceEventBus {
    sender: broadcast::Sender<WorkspaceEvent>,
}

impl Default for InMemoryWorkspaceEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryWorkspaceEventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(256);
        Self { sender }
    }
}

#[async_trait]
impl WorkspaceEventPublisher for InMemoryWorkspaceEventBus {
    async fn publish(&self, event: WorkspaceEvent) {
        let _ = self.sender.send(event);
    }
}

impl WorkspaceEventSubscriber for InMemoryWorkspaceEventBus {
    fn subscribe(&self) -> broadcast::Receiver<WorkspaceEvent> {
        self.sender.subscribe()
    }
}
