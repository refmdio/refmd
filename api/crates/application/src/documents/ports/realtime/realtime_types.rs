use std::pin::Pin;

use futures_util::{Sink, Stream};

use super::realtime_port::RealtimeError;

pub type DynRealtimeSink =
    Pin<Box<dyn Sink<Vec<u8>, Error = RealtimeError> + Send + Sync + 'static>>;
pub type DynRealtimeStream =
    Pin<Box<dyn Stream<Item = Result<Vec<u8>, RealtimeError>> + Send + Sync + 'static>>;
