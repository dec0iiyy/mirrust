//! One-request HTTP/2 exchange, run the way tls.peet.ws runs it.

use std::{fmt, io, time::Duration};

use loona_hpack::Encoder;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::frame::ParsedFrame;
use crate::parser::{self, DEFAULT_MAX_INPUT, Parser, Status};
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
/// The flow-control window of a new connection and of a new stream (RFC 9113 section 6.9.2).
const DEFAULT_WINDOW: i64 = 65_535;
/// The largest flow-control window (RFC 9113 section 6.9.1).
const MAX_WINDOW: i64 = 0x7fff_ffff;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const NO_ERROR: u32 = 0x0;

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
/// The exchange is the one tls.peet.ws runs, made to follow RFC 9113 where that service does
/// not. Once the preface is in, send SETTINGS (initial window 1048576, 100 streams, 65536
/// header list). Read frames until the first one with `END_STREAM`, and answer each SETTINGS
/// frame and each PING with its ACK as it arrives (sections 6.5.3 and 6.7). Call `respond`,
/// except for `OPTIONS`, which gets `options`. On the last HEADERS frame's stream send
/// HEADERS, the body in DATA frames of at most 1024 bytes, an empty DATA with `END_STREAM`,
/// and GOAWAY; wait 500 ms and shut the stream down.
///
/// The body is sent under the client's flow control (section 6.9): never more than the
/// connection's window and the stream's window allow, which are 65,535 bytes each unless the
/// client's SETTINGS and `WINDOW_UPDATE` frames say otherwise. When a window is used up the
/// rest waits, and the frames the client sends meanwhile are read: `WINDOW_UPDATE` and
/// SETTINGS open the window, SETTINGS and PING are acknowledged, `RST_STREAM` on the response's
/// stream or GOAWAY ends the response early, and everything else is ignored, requests on other
/// streams included (the final GOAWAY names the one answered stream, so a client knows the
/// others were not processed). That reading stops at [`DEFAULT_MAX_INPUT`] bytes. A body that
/// fits the windows the client set before its request ended, which is every report a real
/// client asks for, goes out in one write.
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
/// [`ServeError::Io`] when the stream fails or ends first.
///
/// After a protocol error that follows the preface, the client is sent `RST_STREAM` for its
/// request, if a HEADERS frame came, and a GOAWAY frame (section 5.4.1), both with the
/// error's code ([`Error::code`](parser::Error::code)); the GOAWAY has the error's text as
/// debug data. The sending side is shut down, and what the client still sends is read and
/// dropped for up to 500 ms, so that closing the socket does not reset the connection before
/// the client has read the frames. The last stream of the GOAWAY is the highest the client
/// used ([`Parser::last_stream`]), so that the client does not send a refused request again.
/// A request that ends on a stream with no HEADERS frame is refused the same way
/// (`PROTOCOL_ERROR`) but is not an error: the request is returned, as `respond` saw it.
/// Bytes that are not the preface get nothing (section 3.4), and neither does an I/O error.
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
    let mut connection = Connection::new(stream);
    if let Err(error) = connection.read_request(&mut parser, prefix).await {
        let streams = Streams {
            request: parser.request_stream(),
            last: parser.last_stream(),
        };
        connection.refuse(streams, &error).await;
        return Err(error);
    }
    // What came behind the request is the start of what the response phase reads.
    connection.input = parser.unparsed().to_vec();
    let last_stream = parser.last_stream();

    let request = Http2Request::new(parser);
    let response = if request.method == "OPTIONS" {
        options
    } else {
        respond(&request)
    };
    if request.stream_id == 0 {
        // The request ended on a stream that no HEADERS frame opened (RFC 9113 section 5.1).
        let reason = parser::Error::Frame("END_STREAM on a stream without HEADERS");
        let streams = Streams {
            request: 0,
            last: last_stream,
        };
        connection.refuse(streams, &reason.into()).await;
        return Ok(request);
    }
    if let Err(error) = connection.respond(&request, &response, extra_headers).await {
        let streams = Streams {
            request: request.stream_id,
            last: request.stream_id,
        };
        connection.refuse(streams, &error).await;
        return Err(error);
    }
    Ok(request)
}

/// The streams a refusal names.
#[derive(Debug, Clone, Copy)]
struct Streams {
    /// The stream of the client's request, which gets `RST_STREAM`; 0 when there is none.
    request: u32,
    /// The last stream of the GOAWAY frame.
    last: u32,
}

/// The server's side of one exchange.
struct Connection<'s, S> {
    stream: &'s mut S,
    /// Whether the server's SETTINGS frame went out. It must be the first frame the server
    /// sends (RFC 9113 section 3.4), and it is sent once the client's preface is in.
    greeted: bool,
    /// How many of the request's frames have had their acknowledgement sent.
    acknowledged: usize,
    /// Bytes read behind the request that are not parsed yet, from `consumed` on.
    input: Vec<u8>,
    consumed: usize,
    /// Bytes read while the response was written, held to [`DEFAULT_MAX_INPUT`].
    received: usize,
}

impl<'s, S: AsyncRead + AsyncWrite + Unpin> Connection<'s, S> {
    fn new(stream: &'s mut S) -> Self {
        Self {
            stream,
            greeted: false,
            acknowledged: 0,
            input: Vec::new(),
            consumed: 0,
            received: 0,
        }
    }

    /// Reads until `parser` has the first request, `prefix` first.
    async fn read_request(&mut self, parser: &mut Parser, prefix: &[u8]) -> Result<(), ServeError> {
        let mut buf = vec![0; READ_CHUNK];
        let mut status = self.feed(parser, prefix).await?;
        while status == Status::Incomplete {
            let data = read_some(self.stream, &mut buf).await?;
            status = self.feed(parser, data).await?;
        }
        Ok(())
    }

    /// Gives `parser` more bytes and sends at once what they call for: the server's SETTINGS
    /// when the preface is complete, then an ACK for each SETTINGS frame and each PING.
    async fn feed(&mut self, parser: &mut Parser, data: &[u8]) -> Result<Status, ServeError> {
        let result = parser.feed(data);
        if parser.preface_seen() {
            let mut out = Vec::new();
            if !self.greeted {
                out = settings_frame();
                self.greeted = true;
            }
            let frames = parser.frames();
            acknowledge(&mut out, &frames[self.acknowledged..]);
            self.acknowledged = frames.len();
            self.write(&mut out).await?;
        }
        Ok(result?)
    }

    /// Sends HEADERS, as much DATA as the client's windows allow at each point, and GOAWAY.
    async fn respond(
        &mut self,
        request: &Http2Request,
        response: &Response,
        extra_headers: &[(&str, &str)],
    ) -> Result<(), ServeError> {
        let stream_id = request.stream_id;
        // A response to HEAD has no DATA frames, though its `content-length` is that of the
        // body (RFC 9110 section 9.3.2, RFC 9113 section 8.1.1).
        let head = request.method == "HEAD";
        let mut window = SendWindow::new(stream_id);
        for frame in &request.details.sent_frames {
            window.apply(frame);
        }

        let block = header_block(response, extra_headers);
        let mut out = Vec::with_capacity(block.len() + response.body.len() + 64);
        let end_stream = if head { FLAG_END_STREAM } else { 0 };
        push_frame(
            &mut out,
            HEADERS,
            FLAG_END_HEADERS | end_stream,
            stream_id,
            &block,
        );
        let mut body: &[u8] = if head { &[] } else { &response.body };
        let mut buf = Vec::new();
        // Whether the client still takes frames on the stream.
        let mut open = !head;
        loop {
            let (now, later) = body.split_at(body.len().min(window.available()));
            for chunk in now.chunks(DATA_CHUNK) {
                push_frame(&mut out, DATA, 0, stream_id, chunk);
            }
            window.take(now.len());
            body = later;
            if body.is_empty() {
                break;
            }
            // The window is used up (RFC 9113 section 6.9.1): send what fits and wait for
            // the client to open it.
            self.write(&mut out).await?;
            buf.resize(READ_CHUNK, 0);
            let frame = self.next_frame(&mut buf).await?;
            let gone = match frame.frame_type.as_str() {
                "RST_STREAM" => frame.stream_id == stream_id,
                "GOAWAY" => true,
                _ => false,
            };
            if gone {
                open = false;
                break;
            }
            window.apply(&frame);
            acknowledge(&mut out, std::slice::from_ref(&frame));
        }
        if open {
            push_frame(&mut out, DATA, FLAG_END_STREAM, stream_id, &[]);
        }
        push_goaway(&mut out, stream_id, NO_ERROR, &[]);
        self.write(&mut out).await?;
        tokio::time::sleep(CLOSE_DELAY).await;
        self.stream.shutdown().await?;
        Ok(())
    }

    /// The next frame the client sends while the response waits for a window.
    async fn next_frame(&mut self, buf: &mut [u8]) -> Result<ParsedFrame, ServeError> {
        loop {
            if let Some((frame, len)) = parser::frame_at(&self.input[self.consumed..])? {
                self.consumed += len;
                return Ok(frame);
            }
            self.input.drain(..self.consumed);
            self.consumed = 0;
            let data = read_some(self.stream, buf).await?;
            self.received = self.received.saturating_add(data.len());
            if self.received > DEFAULT_MAX_INPUT {
                return Err(parser::Error::TooLarge.into());
            }
            self.input.extend_from_slice(data);
        }
    }

    /// Writes `out`, if there is anything in it, and empties it.
    async fn write(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if !out.is_empty() {
            self.stream.write_all(out).await?;
            self.stream.flush().await?;
            out.clear();
        }
        Ok(())
    }

    /// Ends the connection over what the client sent: `RST_STREAM` for the request and GOAWAY
    /// with the error's code and text, then the sending side is shut down and input is read
    /// and dropped until the client closes or [`CLOSE_DELAY`] has passed. Closing a socket
    /// that has unread input resets the connection, and the reset can reach the client before
    /// it has read the frames.
    ///
    /// Clients differ in what they tell their user. Go's `net/http` prints the GOAWAY frame's
    /// code and debug data. The `h2` crate (hyper, reqwest) reports only a broken pipe for a
    /// request that GOAWAY does not cancel, and curl a framing error; both name the code of an
    /// `RST_STREAM`. A GOAWAY whose last stream is below the request's makes curl and Go send
    /// the request again on a new connection, to be refused again (RFC 9113 section 6.8).
    ///
    /// Nothing is sent for an I/O error, or before the server's SETTINGS: a client that sent
    /// no preface does not speak HTTP/2, and RFC 9113 section 3.4 lets the GOAWAY go.
    async fn refuse(&mut self, streams: Streams, error: &ServeError) {
        let ServeError::Protocol(reason) = error else {
            return;
        };
        if !self.greeted {
            return;
        }
        let mut out = Vec::new();
        if streams.request != 0 {
            push_frame(
                &mut out,
                RST_STREAM,
                0,
                streams.request,
                &reason.code().to_be_bytes(),
            );
        }
        push_goaway(
            &mut out,
            streams.last,
            reason.code(),
            reason.to_string().as_bytes(),
        );
        let farewell = async {
            self.stream.write_all(&out).await?;
            self.stream.flush().await?;
            self.stream.shutdown().await?;
            let mut sink = [0; 1024];
            while self.stream.read(&mut sink).await? != 0 {}
            io::Result::Ok(())
        };
        // Best effort: the caller gets the error that ended the exchange, not this one.
        let _ = tokio::time::timeout(CLOSE_DELAY, farewell).await;
    }
}

/// How much DATA the client lets the server send (RFC 9113 section 6.9): the smaller of the
/// connection's window and the response stream's.
///
/// A window that a client pushes past 2^31 - 1 stays at that value. Section 6.9.1 makes it an
/// error, but tls.peet.ws answers such a client and so does this server: the report is about
/// what the client sent.
#[derive(Debug)]
struct SendWindow {
    stream_id: u32,
    connection: i64,
    stream: i64,
    /// The client's `INITIAL_WINDOW_SIZE`, which `stream` started from.
    initial: i64,
}

impl SendWindow {
    fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            connection: DEFAULT_WINDOW,
            stream: DEFAULT_WINDOW,
            initial: DEFAULT_WINDOW,
        }
    }

    /// Takes a client frame into account: a `WINDOW_UPDATE` for the connection or the stream,
    /// or a SETTINGS frame, whose new `INITIAL_WINDOW_SIZE` moves the stream's window by the
    /// difference from the old one (section 6.9.2), possibly below zero.
    fn apply(&mut self, frame: &ParsedFrame) {
        if let Some(initial) = frame.initial_window {
            let initial = i64::from(initial).min(MAX_WINDOW);
            self.stream = (self.stream + initial - self.initial).min(MAX_WINDOW);
            self.initial = initial;
        }
        if frame.frame_type == "WINDOW_UPDATE" {
            let increment = i64::from(frame.increment);
            if frame.stream_id == 0 {
                self.connection = (self.connection + increment).min(MAX_WINDOW);
            } else if frame.stream_id == self.stream_id {
                self.stream = (self.stream + increment).min(MAX_WINDOW);
            }
        }
    }

    fn available(&self) -> usize {
        usize::try_from(self.connection.min(self.stream)).unwrap_or(0)
    }

    fn take(&mut self, sent: usize) {
        let sent = i64::try_from(sent).expect("no more was sent than a window, which fits");
        self.connection -= sent;
        self.stream -= sent;
    }
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

/// GOAWAY (RFC 9113 section 6.8): the last stream the server acted on, why it ends the
/// connection, and text for whoever debugs the client.
fn push_goaway(out: &mut Vec<u8>, last_stream: u32, code: u32, debug: &[u8]) {
    let mut payload = Vec::with_capacity(8 + debug.len());
    payload.extend_from_slice(&last_stream.to_be_bytes());
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(debug);
    push_frame(out, GOAWAY, 0, 0, &payload);
}

fn settings_frame() -> Vec<u8> {
    let payload: Vec<u8> = SERVER_SETTINGS
        .iter()
        .flat_map(|(id, value)| id.to_be_bytes().into_iter().chain(value.to_be_bytes()))
        .collect();
    let mut out = Vec::with_capacity(9 + payload.len());
    push_frame(&mut out, SETTINGS, 0, 0, &payload);
    out
}

/// A SETTINGS ACK for every SETTINGS frame and a PING ACK for every PING frame in `frames`
/// (RFC 9113 sections 6.5.3 and 6.7).
fn acknowledge(out: &mut Vec<u8>, frames: &[ParsedFrame]) {
    for frame in frames {
        if frame.flags.contains(&"Ack (0x1)") {
            continue;
        }
        match (frame.frame_type.as_str(), frame.ping_data) {
            ("SETTINGS", _) => push_frame(out, SETTINGS, FLAG_ACK, 0, &[]),
            ("PING", Some(data)) => push_frame(out, PING, FLAG_ACK, 0, &data),
            _ => {}
        }
    }
}

/// The HPACK block of the response's headers.
fn header_block(response: &Response, extra_headers: &[(&str, &str)]) -> Vec<u8> {
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
    Encoder::new().encode(fields)
}
