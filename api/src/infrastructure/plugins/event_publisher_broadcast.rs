use async_trait::async_trait;

use crate::application::ports::plugin_event_publisher::{PluginEventPublisher, PluginScopedEvent};

#[derive(Clone)]
pub struct BroadcastPluginEventPublisher {
    sender: tokio::sync::broadcast::Sender<PluginScopedEvent>,
}

impl BroadcastPluginEventPublisher {
    pub fn new(sender: tokio::sync::broadcast::Sender<PluginScopedEvent>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl PluginEventPublisher for BroadcastPluginEventPublisher {
    async fn publish(&self, event: &PluginScopedEvent) -> anyhow::Result<()> {
        match self.sender.send(event.clone()) {
            Ok(_) => Ok(()),
            // No active subscribers is harmless; don't propagate a 500 back to the caller.
            Err(tokio::sync::broadcast::error::SendError(_)) => Ok(()),
        }
    }
}
