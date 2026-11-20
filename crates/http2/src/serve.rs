//! One-request HTTP/2 exchange, run the way tls.peet.ws runs it.

use std::{fmt, io, time::Duration};

use loona_hpack::Encoder;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::frame::ParsedFrame;
use crate::parser::{self, Parser, Status};
use crate::request::Http2Request;

/// What the caller answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code, such as 200 or 404.
    pub status: u16,
    /// `content-type` value, sent as is (no charset is added on HTTP/2).
    pub content_type: String,
    /// Response body.
    pub body: Vec<u8>,
    /// Adds the three `access-control-allow-*: *` headers, for requests carrying the CORS key.
    pub allow_cors: bool,
    /// `alt-svc` value, such as `h3=":443"; ma=86400`; `None` sends no `alt-svc`.
    pub alt_svc: Option<String>,
}

impl Default for Response {
    /// An empty `200` response.
    fn default() -> Self {
        Self {
            status: 200,
            content_type: String::new(),
            body: Vec::new(),
            allow_cors: false,
            alt_svc: None,
        }
    }
}

/// Why [`serve`] ended without answering.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServeError {
    /// Reading or writing the stream failed, or the client closed it early.
    Io(io::Error),
    /// The client's bytes are not what tls.peet.ws accepts.
    Protocol(parser::Error),
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("http/2 connection i/o failed"),
            Self::Protocol(_) => f.write_str("http/2 client sent invalid input"),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Protocol(err) => Some(err),
        }
    }
}

impl From<io::Error> for ServeError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<parser::Error> for ServeError {
    fn from(err: parser::Error) -> Self {
        Self::Protocol(err)
    }
}

/// Server SETTINGS, in order: the ones tls.peet.ws sends.
const SERVER_SETTINGS: [(u16, u32); 3] = [(4, 1_048_576), (3, 100), (6, 65_536)];
/// tls.peet.ws splits the body into DATA frames of this size.
const DATA_CHUNK: usize = 1024;
/// tls.peet.ws waits this long after GOAWAY before closing.
const CLOSE_DELAY: Duration = Duration::from_millis(500);
const READ_CHUNK: usize = 16 * 1024;

/// Reads one HTTP/2 request from `stream`, starting at the connection preface, and answers it.
///
/// See [`serve_with_prefix`] for the exchange, for `extra_headers` and for `options`.
///
/// # Errors
///
/// As [`serve_with_prefix`].
pub async fn serve<S, F>(
    stream: &mut S,
    extra_headers: &[(&str, &str)],
    options: Response,
    respond: F,
) -> Result<Http2Request, ServeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&Http2Request) -> Response,
{
    serve_with_prefix(stream, &[], extra_headers, options, respond).await
}

/// Like [`serve`], for a caller that already read `prefix` (the preface and maybe more) off
/// `stream` to tell HTTP/2 from HTTP/1.
///
/// The exchange matches tls.peet.ws: once the preface is in, send SETTINGS (initial window
/// 1048576, 100 streams, 65536 header list); read frames until
/// the first one with `END_STREAM`; call `respond`, except for `OPTIONS`, which gets
/// `options`; send a SETTINGS ACK for each SETTINGS frame and a PING ACK for each PING frame read,
/// then on the last HEADERS frame's stream send
/// HEADERS, the body in 1024-byte DATA frames, an empty DATA with `END_STREAM`, and GOAWAY;
/// wait 500 ms and shut the stream down. If no HEADERS frame came, nothing is answered.
///
/// `extra_headers` are `(name, value)` pairs sent on every response, the `OPTIONS` answer
/// included, after the headers [`Response`] describes. Names are sent in lowercase, as HTTP/2
/// requires, whatever case they are given in.
///
/// `options` is the answer to an `OPTIONS` request, which `respond` never sees. The caller
/// builds it, so it can match what the caller's other protocols send: an empty body, the
/// `content-type` and `alt-svc` it uses elsewhere, and `allow_cors` set.
///
/// # Errors
///
/// [`ServeError::Protocol`] when the client's bytes are not a request tls.peet.ws answers, and
/// [`ServeError::Io`] when the stream fails or ends first. The stream is not shut down on
/// error; dropping it closes the connection, as tls.peet.ws does.
pub async fn serve_with_prefix<S, F>(
    stream: &mut S,
    prefix: &[u8],
    extra_headers: &[(&str, &str)],
    options: Response,
    respond: F,
) -> Result<Http2Request, ServeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&Http2Request) -> Response,
{
    let mut parser = Parser::new();
    let mut status = parser.feed(prefix)?;
    let mut buf = vec![0; READ_CHUNK];
    while !parser.preface_seen() {
        status = parser.feed(read_some(stream, &mut buf).await?)?;
    }
    stream.write_all(&settings_frame()).await?;
    stream.flush().await?;
    while status == Status::Incomplete {
        status = parser.feed(read_some(stream, &mut buf).await?)?;
    }

    let request = Http2Request::new(parser);
    let response = if request.method == "OPTIONS" {
        options
    } else {
        respond(&request)
    };
    if request.stream_id == 0 {
        // Go's Framer refuses to write HEADERS on stream 0 and tls.peet.ws gives up silently.
        return Ok(request);
    }
    let mut answer = acknowledgements(&request.details.sent_frames);
    answer.extend(response_frames(
        request.stream_id,
        &response,
        extra_headers,
        request.method == "HEAD",
    ));
    stream.write_all(&answer).await?;
    stream.flush().await?;
    tokio::time::sleep(CLOSE_DELAY).await;
    stream.shutdown().await?;
    Ok(request)
}

async fn read_some<'b, S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &'b mut [u8],
) -> io::Result<&'b [u8]> {
    let n = stream.read(buf).await?;
    if n == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(&buf[..n])
}

fn push_frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    let len = u32::try_from(payload.len()).expect("frames are built from bounded chunks");
    out.extend_from_slice(&len.to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
}

fn settings_frame() -> Vec<u8> {
    let payload: Vec<u8> = SERVER_SETTINGS
        .iter()
        .flat_map(|(id, value)| id.to_be_bytes().into_iter().chain(value.to_be_bytes()))
        .collect();
    let mut out = Vec::with_capacity(9 + payload.len());
    push_frame(&mut out, 0x4, 0, 0, &payload);
    out
}

/// A SETTINGS ACK for every SETTINGS frame and a PING ACK for every PING frame the client sent
/// (RFC 9113 sections 6.5.3 and 6.7); the exchange has no other use for them, so they go out
/// together with the response instead of one by one as the frames arrive.
fn acknowledgements(frames: &[ParsedFrame]) -> Vec<u8> {
    let mut out = Vec::new();
    for frame in frames {
        if frame.flags.contains(&"Ack (0x1)") {
            continue;
        }
        match (frame.frame_type.as_str(), frame.ping_data) {
            ("SETTINGS", _) => push_frame(&mut out, 0x4, 0x1, 0, &[]),
            ("PING", Some(data)) => push_frame(&mut out, 0x6, 0x1, 0, &data),
            _ => {}
        }
    }
    out
}

/// HEADERS, DATA and GOAWAY for `response`. A response to HEAD has no DATA frames, though its
/// `content-length` is that of the body (RFC 9110 section 9.3.2, RFC 9113 section 8.1.1).
fn response_frames(
    stream_id: u32,
    response: &Response,
    extra_headers: &[(&str, &str)],
    head: bool,
) -> Vec<u8> {
    let length = response.body.len().to_string();
    let status = response.status.to_string();
    let extra_names: Vec<String> = extra_headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();
    let mut fields: Vec<(&[u8], &[u8])> = vec![
        (b":status", status.as_bytes()),
        (b"server", b"mirrust"),
        (b"content-length", length.as_bytes()),
        (b"content-type", response.content_type.as_bytes()),
    ];
    if let Some(alt_svc) = &response.alt_svc {
        fields.push((b"alt-svc", alt_svc.as_bytes()));
    }
    if response.allow_cors {
        fields.extend([
            (&b"access-control-allow-origin"[..], &b"*"[..]),
            (b"access-control-allow-methods", b"*"),
            (b"access-control-allow-headers", b"*"),
        ]);
    }
    fields.extend(
        extra_names
            .iter()
            .zip(extra_headers)
            .map(|(name, (_, value))| (name.as_bytes(), value.as_bytes())),
    );
    let block = Encoder::new().encode(fields);

    let mut out = Vec::with_capacity(block.len() + response.body.len() + 64);
    if head {
        // END_HEADERS | END_STREAM
        push_frame(&mut out, 0x1, 0x5, stream_id, &block);
    } else {
        push_frame(&mut out, 0x1, 0x4, stream_id, &block);
        for chunk in response.body.chunks(DATA_CHUNK) {
            push_frame(&mut out, 0x0, 0, stream_id, chunk);
        }
        push_frame(&mut out, 0x0, 0x1, stream_id, &[]);
    }
    let mut goaway = [0; 8];
    goaway[..4].copy_from_slice(&stream_id.to_be_bytes());
    push_frame(&mut out, 0x7, 0, 0, &goaway);
    out
}
