use std::{pin::Pin, sync::Arc};

use futures_util::{Sink, Stream};
use tokio::sync::Mutex;

use crate::application::ports::realtime_port::RealtimeError;

pub type DynRealtimeSink =
    Arc<Mutex<Pin<Box<dyn Sink<Vec<u8>, Error = RealtimeError> + Send + Sync + 'static>>>>;
pub type DynRealtimeStream =
    Pin<Box<dyn Stream<Item = Result<Vec<u8>, RealtimeError>> + Send + Sync + 'static>>;

mod hub;
mod realtime_port_impl;
pub use hub::*;
// Keep backward-compatible module path `port_impl`
pub mod port_impl {
    pub use super::realtime_port_impl::*;
}
