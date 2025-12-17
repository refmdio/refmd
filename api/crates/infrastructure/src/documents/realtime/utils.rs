use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use anyhow::Result;
use futures_util::Stream;
use tracing::{debug, warn};
use yrs::encoding::read::Cursor;
use yrs::sync::{Message, MessageReader, SyncMessage};
use yrs::updates::decoder::DecoderV1;

use application::documents::ports::realtime::realtime_port::RealtimeError;
use application::documents::ports::realtime::realtime_types::DynRealtimeStream;

pub fn analyse_frame(frame: &[u8]) -> Result<FrameSummary> {
    let mut decoder = DecoderV1::new(Cursor::new(frame));
    let mut reader = MessageReader::new(&mut decoder);
    let mut summary = FrameSummary::default();
    while let Some(message) = reader.next() {
        match message? {
            Message::Sync(SyncMessage::Update(_)) | Message::Sync(SyncMessage::SyncStep2(_)) => {
                summary.has_update = true;
            }
            Message::Awareness(_) => {
                summary.has_awareness = true;
            }
            _ => {}
        }
    }
    Ok(summary)
}

#[derive(Default, Clone, Copy, Debug)]
pub struct FrameSummary {
    pub has_update: bool,
    pub has_awareness: bool,
}

pub fn wrap_stream_with_edit_guard(
    stream: DynRealtimeStream,
    doc_id: String,
    flag: Arc<AtomicBool>,
) -> DynRealtimeStream {
    Box::pin(GuardedStream {
        inner: stream,
        doc_id,
        flag,
    })
}

struct GuardedStream {
    inner: DynRealtimeStream,
    doc_id: String,
    flag: Arc<AtomicBool>,
}

impl Stream for GuardedStream {
    type Item = StdResult<Vec<u8>, RealtimeError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if !self.flag.load(Ordering::Relaxed) {
                        match analyse_frame(&frame) {
                            Ok(summary) if summary.has_update => {
                                warn!(
                                    document_id = %self.doc_id,
                                    "ignored_update_from_readonly_document"
                                );
                                continue;
                            }
                            Err(e) => {
                                debug!(
                                    document_id = %self.doc_id,
                                    error = ?e,
                                    "failed_to_decode_frame_for_edit_guard"
                                );
                                // treat undecodable frames as non-updates to avoid disconnect loops
                            }
                            _ => {}
                        }
                    }
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
