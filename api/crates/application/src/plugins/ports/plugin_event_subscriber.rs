use async_trait::async_trait;
use futures_util::stream::BoxStream;

use crate::core::ports::errors::PortResult;
use crate::plugins::ports::plugin_event_publisher::PluginScopedEvent;

#[async_trait]
pub trait PluginEventSubscriber: Send + Sync {
    async fn subscribe(&self) -> PortResult<BoxStream<'static, PluginScopedEvent>>;
}
