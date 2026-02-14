//! In-memory device event bus for single-node deployments

use application::events::{DeviceEventPublisher, DeviceEventSubscriber};
use async_trait::async_trait;
use domain::DeviceEvent;
use tokio::sync::broadcast;

/// In-memory event bus for single-node deployments
#[derive(Clone)]
pub struct InMemoryDeviceEventBus {
    sender: broadcast::Sender<DeviceEvent>,
}

impl Default for InMemoryDeviceEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryDeviceEventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(256);
        Self { sender }
    }
}

#[async_trait]
impl DeviceEventPublisher for InMemoryDeviceEventBus {
    async fn publish(&self, event: DeviceEvent) {
        let _ = self.sender.send(event);
    }
}

impl DeviceEventSubscriber for InMemoryDeviceEventBus {
    fn subscribe(&self) -> broadcast::Receiver<DeviceEvent> {
        self.sender.subscribe()
    }
}

