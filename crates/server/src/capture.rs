//! Reads the ClientHello off the socket before the TLS library sees it, then replays it.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// Largest ClientHello, with its record headers, that is buffered before giving up.
/// Post-quantum hellos are about 2 KiB; 64 KiB leaves room for any real client.
pub(crate) const MAX_HELLO_BYTES: usize = 64 * 1024;

const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;

/// Reads TLS records until one whole handshake message is assembled.
///
/// Returns every byte read from `stream` (to replay to the TLS library) and the
/// ClientHello message itself, from its type byte on, without record headers.
pub(crate) async fn read_client_hello<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut message = Vec::new();
    let mut record_start = 0;
    loop {
        if let Some(len) = message_len(&message)?
            && message.len() >= len
        {
            message.truncate(len);
            return Ok((raw, message));
        }
        let body_start = record_start + RECORD_HEADER_LEN;
        fill_to(stream, &mut raw, body_start).await?;
        let header = &raw[record_start..body_start];
        if header[0] != CONTENT_TYPE_HANDSHAKE {
            return Err(invalid("first record is not a TLS handshake record"));
        }
        let body_end = body_start + usize::from(u16::from_be_bytes([header[3], header[4]]));
        if body_end > MAX_HELLO_BYTES {
            return Err(invalid("ClientHello is larger than 64 KiB"));
        }
        fill_to(stream, &mut raw, body_end).await?;
        message.extend_from_slice(&raw[body_start..body_end]);
        record_start = body_end;
        if message
            .first()
            .is_some_and(|&kind| kind != HANDSHAKE_CLIENT_HELLO)
        {
            return Err(invalid("first handshake message is not a ClientHello"));
        }
    }
}

/// Full length of the handshake message once its 4-byte header is in.
fn message_len(message: &[u8]) -> io::Result<Option<usize>> {
    let Some(header) = message.get(..HANDSHAKE_HEADER_LEN) else {
        return Ok(None);
    };
    let body = usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
    let len = HANDSHAKE_HEADER_LEN + body;
    if len > MAX_HELLO_BYTES {
        return Err(invalid("ClientHello is larger than 64 KiB"));
    }
    Ok(Some(len))
}

async fn fill_to<R: AsyncRead + Unpin>(
    stream: &mut R,
    raw: &mut Vec<u8>,
    need: usize,
) -> io::Result<()> {
    let mut chunk = [0; 4096];
    while raw.len() < need {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, NotTls(message))
}

/// Why the bytes a client opened with are not a ClientHello. It is the source of the
/// `InvalidData` errors of [`read_client_hello`], which lets the failure summary tell them
/// from the `InvalidData` errors rustls reports.
#[derive(Debug)]
pub(crate) struct NotTls(pub(crate) &'static str);

impl fmt::Display for NotTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for NotTls {}

/// A stream that first yields bytes already read from it, then reads from it as usual.
/// Writes go straight through.
#[derive(Debug)]
pub(crate) struct Rewind<S> {
    buffered: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Rewind<S> {
    pub(crate) fn new(buffered: Vec<u8>, inner: S) -> Self {
        Self {
            buffered,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let rest = &this.buffered[this.pos..];
        if rest.is_empty() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let n = rest.len().min(buf.remaining());
        buf.put_slice(&rest[..n]);
        this.pos += n;
        if this.pos == this.buffered.len() {
            this.buffered = Vec::new();
            this.pos = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(body: &[u8]) -> Vec<u8> {
        let len = u16::try_from(body.len()).expect("test record fits");
        let mut out = vec![CONTENT_TYPE_HANDSHAKE, 3, 1];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn assembles_a_hello_split_over_records_and_replays_everything() {
        let message = [1, 0, 0, 3, 0xaa, 0xbb, 0xcc];
        let mut wire = record(&message[..2]);
        wire.extend(record(&message[2..]));
        wire.extend_from_slice(b"after");
        let mut input = wire.as_slice();

        let (raw, got) = read_client_hello(&mut input).await.expect("valid hello");
        assert_eq!(got, message);

        let mut replay = Rewind::new(raw, input);
        let mut all = Vec::new();
        replay.read_to_end(&mut all).await.expect("replay reads");
        assert_eq!(all, wire);
    }

    #[tokio::test]
    async fn rejects_non_handshake_records() {
        let mut input: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
        let err = read_client_hello(&mut input).await.expect_err("plain HTTP");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_oversized_hellos() {
        let mut input: &[u8] = &record(&[1, 0x01, 0x00, 0x00]);
        let err = read_client_hello(&mut input).await.expect_err("too big");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
