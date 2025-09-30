use std::pin::Pin;
use std::sync::Arc;

use futures_util::{Sink, Stream};
use tokio::sync::Mutex;

use super::realtime_port::RealtimeError;

pub type DynRealtimeSink =
    Arc<Mutex<Pin<Box<dyn Sink<Vec<u8>, Error = RealtimeError> + Send + Sync + 'static>>>>;
pub type DynRealtimeStream =
    Pin<Box<dyn Stream<Item = Result<Vec<u8>, RealtimeError>> + Send + Sync + 'static>>;
