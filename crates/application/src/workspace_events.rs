//! Workspace event bus traits
//!
//! Defines the event publishing and subscribing contracts used by application-layer
//! handlers and presentation-layer SSE routes. Implementations live in the
//! infrastructure layer.

use async_trait::async_trait;
use domain::WorkspaceEvent;
use tokio::sync::broadcast;

/// Trait for publishing workspace events from the application layer.
#[async_trait]
pub trait WorkspaceEventPublisher: Send + Sync {
    /// Publish a workspace event.
    async fn publish(&self, event: WorkspaceEvent);
}

/// Trait for subscribing to workspace events (used by SSE routes).
pub trait WorkspaceEventSubscriber: Send + Sync {
    /// Subscribe to events.
    fn subscribe(&self) -> broadcast::Receiver<WorkspaceEvent>;
}

/// Combined publish + subscribe trait for convenience.
pub trait WorkspaceEventBus: WorkspaceEventPublisher + WorkspaceEventSubscriber {}

impl<T: WorkspaceEventPublisher + WorkspaceEventSubscriber> WorkspaceEventBus for T {}
