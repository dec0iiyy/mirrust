//! An `h3_quinn` connection that keeps a copy of the first bytes of every unidirectional
//! stream the client opens.
//!
//! `h3` reads the client's control stream itself and shows neither its SETTINGS frame nor the
//! stream types. [`TapConnection`] implements the `h3::quic` traits by passing every call to
//! `h3_quinn`; the receive streams it hands to `h3` copy what they read into [`UniStreams`],
//! from which the request handler builds the `http3` object. Requests wait until the SETTINGS
//! frame has been read, for at most [`SETTINGS_WAIT`], so the first report already has it.

use std::future::Future as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId};
use http3::Http3Details;
use tokio::time::Sleep;

/// Bytes kept per stream. A SETTINGS frame takes a few dozen; the rest of a control or QPACK
/// stream is not needed.
const MAX_STREAM_PREFIX: usize = 1024;

/// Streams kept per connection. Clients open three or four.
pub(crate) const MAX_STREAMS: usize = 16;

/// How long requests wait for the client's SETTINGS frame, counted from the end of the
/// handshake. Clients send it in their first flight of stream data; one that never does gets
/// its answer this much later, with `settings: null`.
const SETTINGS_WAIT: Duration = Duration::from_millis(250);

/// The first bytes of each unidirectional stream a client opened, shared between the
/// connection's streams and its request handler.
#[derive(Debug, Clone, Default)]
pub(crate) struct UniStreams {
    /// In the order the streams were accepted.
    streams: Arc<Mutex<Vec<Prefix>>>,
}

/// QUIC stream id and the stream's first bytes.
type Prefix = (u64, Vec<u8>);

impl UniStreams {
    /// The `http3` object built from what has been read so far.
    pub(crate) fn details(&self) -> Http3Details {
        let streams = self.lock();
        Http3Details::new(streams.iter().map(|(id, prefix)| (*id, prefix.as_slice())))
    }

    fn has_settings(&self) -> bool {
        self.lock()
            .iter()
            .any(|(_, prefix)| http3::has_settings(prefix))
    }

    /// Starts a stream's entry; `None` once the connection has [`MAX_STREAMS`].
    fn open(&self, id: StreamId) -> Option<usize> {
        let mut streams = self.lock();
        (streams.len() < MAX_STREAMS).then(|| {
            streams.push((id.into_inner(), Vec::new()));
            streams.len() - 1
        })
    }

    fn append(&self, index: usize, bytes: &[u8]) {
        if let Some((_, prefix)) = self.lock().get_mut(index) {
            let room = MAX_STREAM_PREFIX.saturating_sub(prefix.len());
            prefix.extend_from_slice(&bytes[..bytes.len().min(room)]);
        }
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Prefix>> {
        self.streams.lock().expect("stream prefix lock poisoned")
    }
}

/// `h3_quinn::Connection` with every client-opened unidirectional stream tapped.
pub(crate) struct TapConnection {
    inner: h3_quinn::Connection,
    streams: UniStreams,
    /// Runs out when requests stop waiting for SETTINGS; `None` once they no longer wait.
    settings_wait: Option<Pin<Box<Sleep>>>,
}

impl TapConnection {
    /// Wraps `inner`; the second value reads what the streams have shown.
    pub(crate) fn new(inner: h3_quinn::Connection) -> (Self, UniStreams) {
        let streams = UniStreams::default();
        let tap = Self {
            inner,
            streams: streams.clone(),
            settings_wait: Some(Box::pin(tokio::time::sleep(SETTINGS_WAIT))),
        };
        (tap, streams)
    }
}

impl<B: Buf> quic::Connection<B> for TapConnection {
    type RecvStream = TapRecvStream;
    type OpenStreams = h3_quinn::OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        let accepted =
            <h3_quinn::Connection as quic::Connection<B>>::poll_accept_recv(&mut self.inner, cx);
        accepted.map_ok(|inner| {
            let index = self.streams.open(quic::RecvStream::recv_id(&inner));
            TapRecvStream {
                inner,
                streams: self.streams.clone(),
                index,
            }
        })
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        // `h3` polls the unidirectional streams before it asks for a request stream, and their
        // wakers and the timer wake this task again, so returning `Pending` here loses nothing.
        if let Some(wait) = &mut self.settings_wait {
            if !self.streams.has_settings() && wait.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.settings_wait = None;
        }
        <h3_quinn::Connection as quic::Connection<B>>::poll_accept_bidi(&mut self.inner, cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        <h3_quinn::Connection as quic::Connection<B>>::opener(&self.inner)
    }
}

impl<B: Buf> quic::OpenStreams<B> for TapConnection {
    type BidiStream = h3_quinn::BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        <h3_quinn::Connection as quic::OpenStreams<B>>::poll_open_bidi(&mut self.inner, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        <h3_quinn::Connection as quic::OpenStreams<B>>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::Connection as quic::OpenStreams<B>>::close(&mut self.inner, code, reason);
    }
}

/// A client-opened unidirectional stream that copies its first bytes into [`UniStreams`].
pub(crate) struct TapRecvStream {
    inner: h3_quinn::RecvStream,
    streams: UniStreams,
    /// The stream's entry in `streams`; `None` when the connection opened too many.
    index: Option<usize>,
}

impl quic::RecvStream for TapRecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        let data = self.inner.poll_data(cx);
        if let (Poll::Ready(Ok(Some(bytes))), Some(index)) = (&data, self.index) {
            self.streams.append(index, bytes);
        }
        data
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}
