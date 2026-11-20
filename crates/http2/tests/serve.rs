//! `serve` against a real HTTP/2 client (the `h2` crate) over an in-memory stream.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use http2::{Parser, Response, Status, akamai_fingerprint, serve};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

/// Client end of the duplex that keeps a copy of everything the client writes.
struct Recording {
    inner: DuplexStream,
    sent: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Recording {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Recording {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = poll {
            self.sent.lock().expect("lock").extend_from_slice(&buf[..n]);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn h2_client_reads_the_response_and_fingerprint_matches_its_bytes() {
    let (client_io, mut server_io) = tokio::io::duplex(1 << 16);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let client_io = Recording {
        inner: client_io,
        sent: Arc::clone(&sent),
    };

    let body: Vec<u8> = (0..2500u32).map(|i| b'a' + (i % 26) as u8).collect();
    let served_body = body.clone();
    let server = tokio::spawn(async move {
        let extra = [("X-Extra", "one"), ("cache-control", "no-store")];
        serve(
            &mut server_io,
            &extra,
            Response::default(),
            move |request| Response {
                status: 200,
                content_type: "application/json".to_owned(),
                body: if request.path == "/api/all" {
                    served_body
                } else {
                    Vec::new()
                },
                allow_cors: false,
                alt_svc: Some("h3=\":443\"; ma=86400".to_owned()),
            },
        )
        .await
    });

    let (mut sender, connection) = h2::client::Builder::new()
        .enable_push(false)
        .initial_window_size(1_000_000)
        .handshake::<_, bytes::Bytes>(client_io)
        .await
        .expect("handshake");
    let driver = tokio::spawn(connection);

    let request = http::Request::get("https://example.test/api/all")
        .header("user-agent", "h2-test")
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    let response = response.await.expect("response");
    assert_eq!(response.status(), 200);
    let headers = response.headers();
    assert_eq!(headers["server"], "mirrust");
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(headers["content-length"], "2500");
    assert_eq!(headers["alt-svc"], "h3=\":443\"; ma=86400");
    // The h2 client rejects a header block with an uppercase name, so this also shows the
    // name was lowercased.
    assert_eq!(headers["x-extra"], "one");
    assert_eq!(headers["cache-control"], "no-store");
    assert!(!headers.contains_key("access-control-allow-origin"));

    let mut stream = response.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.expect("data");
        stream
            .flow_control()
            .release_capacity(chunk.len())
            .expect("release");
        got.extend_from_slice(&chunk);
    }
    assert_eq!(got, body);

    let request = server.await.expect("join").expect("serve");
    drop(sender);
    let _ = driver.await;

    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/all");
    assert_eq!(request.user_agent, "h2-test");
    assert_eq!(request.stream_id, 1);

    let sent = sent.lock().expect("lock").clone();
    let mut parser = Parser::new();
    assert_eq!(
        parser.feed(&sent).expect("client bytes parse"),
        Status::Complete
    );
    assert_eq!(
        request.details.akamai_fingerprint,
        akamai_fingerprint(parser.frames())
    );
    let fingerprint = &request.details.akamai_fingerprint;
    assert!(
        fingerprint.starts_with("2:0;4:1000000") && fingerprint.ends_with("|0|m,s,a,p"),
        "{fingerprint}"
    );
}

#[tokio::test]
async fn options_gets_cors_and_extra_headers_and_an_empty_body() {
    let (client_io, mut server_io) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        let options = Response {
            content_type: "text/plain; charset=utf-8".to_owned(),
            allow_cors: true,
            alt_svc: Some("h3=\":443\"; ma=86400".to_owned()),
            ..Response::default()
        };
        serve(&mut server_io, &[("x-extra", "one")], options, |_| {
            panic!("OPTIONS must not reach the callback")
        })
        .await
    });
    let (mut sender, connection) = h2::client::handshake(client_io).await.expect("handshake");
    tokio::spawn(connection);
    let request = http::Request::builder()
        .method("OPTIONS")
        .uri("https://example.test/")
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    let response = response.await.expect("response");
    assert_eq!(response.headers()["access-control-allow-origin"], "*");
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; charset=utf-8"
    );
    assert_eq!(response.headers()["alt-svc"], "h3=\":443\"; ma=86400");
    assert_eq!(response.headers()["access-control-allow-methods"], "*");
    assert_eq!(response.headers()["content-length"], "0");
    assert_eq!(response.headers()["x-extra"], "one");
    assert_eq!(
        server.await.expect("join").expect("serve").method,
        "OPTIONS"
    );
}

#[tokio::test]
async fn head_gets_the_headers_of_the_body_and_no_data_frames() {
    let (client_io, mut server_io) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        serve(&mut server_io, &[], Response::default(), |_| Response {
            body: b"twelve bytes".to_vec(),
            ..Response::default()
        })
        .await
    });
    let (mut sender, connection) = h2::client::handshake(client_io).await.expect("handshake");
    tokio::spawn(connection);
    let request = http::Request::builder()
        .method("HEAD")
        .uri("https://example.test/")
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    let response = response.await.expect("response");
    assert_eq!(response.headers()["content-length"], "12");
    let mut body = response.into_body();
    assert!(
        body.data().await.is_none(),
        "RFC 9110 section 9.3.2: no content in the response to HEAD"
    );
    server.await.expect("join").expect("serve");
}

/// `(type, flags, stream, payload)` of each frame in `bytes`.
fn frames_of(mut bytes: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
    let mut frames = Vec::new();
    while bytes.len() >= 9 {
        let len = usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]);
        let stream = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        frames.push((bytes[3], bytes[4], stream, bytes[9..9 + len].to_vec()));
        bytes = &bytes[9 + len..];
    }
    frames
}

fn raw_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("small");
    let mut out = len.to_be_bytes()[1..].to_vec();
    out.extend([kind, flags]);
    out.extend(stream.to_be_bytes());
    out.extend(payload);
    out
}

#[tokio::test]
async fn settings_and_ping_are_acknowledged() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let (mut client_io, mut server_io) = tokio::io::duplex(1 << 16);
    let mut input = http2::PREFACE.to_vec();
    input.extend(raw_frame(0x4, 0, 0, &[]));
    input.extend(raw_frame(0x6, 0, 0, b"pingdata"));
    // GET / https: the static table entries 2, 7 and 4, with END_STREAM and END_HEADERS.
    input.extend(raw_frame(0x1, 0x5, 1, &[0x82, 0x87, 0x84]));
    client_io.write_all(&input).await.expect("write");
    let result = serve(&mut server_io, &[], Response::default(), |_| {
        Response::default()
    })
    .await;
    result.expect("serve");
    drop(server_io);
    let mut output = Vec::new();
    client_io.read_to_end(&mut output).await.expect("read");

    let frames = frames_of(&output);
    let acks: Vec<_> = frames
        .iter()
        .filter(|(kind, flags, ..)| matches!(kind, 0x4 | 0x6) && flags & 1 == 1)
        .map(|(kind, _, stream, payload)| (*kind, *stream, payload.clone()))
        .collect();
    assert_eq!(
        acks,
        [(0x4, 0, vec![]), (0x6, 0, b"pingdata".to_vec())],
        "RFC 9113 sections 6.5.3 and 6.7: {frames:?}"
    );
}

#[tokio::test]
async fn garbage_is_an_error_not_a_panic_and_gets_no_frames() {
    let (result, output) = exchange(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec()).await;
    assert!(matches!(
        result,
        Err(http2::ServeError::Protocol(http2::Error::BadPreface))
    ));
    // RFC 9113 section 3.4: a GOAWAY may be omitted for a client that sent no preface.
    assert_eq!(output, []);
}

/// Reads the server's frames off the client end of a duplex, one at a time.
#[derive(Default)]
struct FrameReader {
    buf: Vec<u8>,
    /// `(type, flags, stream, payload)` of every frame read so far.
    frames: Vec<(u8, u8, u32, Vec<u8>)>,
}

impl FrameReader {
    async fn next(&mut self, io: &mut DuplexStream) {
        use tokio::io::AsyncReadExt as _;
        loop {
            if self.buf.len() >= 9 {
                let len = usize::from(self.buf[0]) << 16
                    | usize::from(self.buf[1]) << 8
                    | usize::from(self.buf[2]);
                if self.buf.len() >= 9 + len {
                    let frame: Vec<u8> = self.buf.drain(..9 + len).collect();
                    self.frames.extend(frames_of(&frame));
                    return;
                }
            }
            let mut chunk = [0; 4096];
            let n = io.read(&mut chunk).await.expect("read");
            assert!(n > 0, "the server closed after {:?}", self.frames);
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Reads frames until `done` says so; panics if the server sends nothing for a second.
    async fn until(&mut self, io: &mut DuplexStream, done: impl Fn(&Self) -> bool) {
        while !done(self) {
            tokio::time::timeout(Duration::from_secs(1), self.next(io))
                .await
                .unwrap_or_else(|_| panic!("no frame for a second after {:?}", self.frames));
        }
    }

    /// Whether the server sends nothing more for 100 ms.
    async fn is_quiet(&mut self, io: &mut DuplexStream) -> bool {
        tokio::time::timeout(Duration::from_millis(100), self.next(io))
            .await
            .is_err()
    }

    /// Bytes of DATA payload received.
    fn data_len(&self) -> usize {
        self.frames
            .iter()
            .filter(|(kind, ..)| *kind == 0x0)
            .map(|(.., payload)| payload.len())
            .sum()
    }

    fn has(&self, kind: u8, flags: u8) -> bool {
        self.frames
            .iter()
            .any(|(k, f, ..)| *k == kind && *f == flags)
    }
}

/// `SETTINGS` with one `INITIAL_WINDOW_SIZE`.
fn initial_window(size: u32) -> Vec<u8> {
    let mut payload = vec![0, 4];
    payload.extend(size.to_be_bytes());
    raw_frame(0x4, 0, 0, &payload)
}

/// GET / https on stream 1: the static table entries 2, 7 and 4, `END_STREAM | END_HEADERS`.
fn get_request() -> Vec<u8> {
    raw_frame(0x1, 0x5, 1, &[0x82, 0x87, 0x84])
}

fn serve_body(
    mut server_io: DuplexStream,
    body: Vec<u8>,
) -> tokio::task::JoinHandle<Result<http2::Http2Request, http2::ServeError>> {
    tokio::spawn(async move {
        serve(&mut server_io, &[], Response::default(), move |_| {
            Response {
                body,
                ..Response::default()
            }
        })
        .await
    })
}

#[tokio::test]
async fn h2_client_with_default_windows_reads_a_body_larger_than_them() {
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    let body: Vec<u8> = (0..200_000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let server = serve_body(server_io, body.clone());

    // The defaults of the `h2` crate, and so of hyper and reqwest: 65,535 bytes for the
    // stream and for the connection (RFC 9113 section 6.9.2). `h2` ends the connection with
    // FLOW_CONTROL_ERROR when a server sends more than a window holds.
    let (mut sender, connection) = h2::client::handshake(client_io).await.expect("handshake");
    tokio::spawn(connection);
    let request = http::Request::get("https://example.test/")
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    let response = response.await.expect("response");
    assert_eq!(response.headers()["content-length"], "200000");
    let mut stream = response.into_body();
    let mut got = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.expect("data within the window");
        stream
            .flow_control()
            .release_capacity(chunk.len())
            .expect("release");
        got.extend_from_slice(&chunk);
    }
    assert!(got == body, "{} of {} bytes", got.len(), body.len());
    server.await.expect("join").expect("serve");
}

#[tokio::test]
async fn the_body_waits_for_the_stream_window() {
    use tokio::io::AsyncWriteExt as _;
    let (mut client, server_io) = tokio::io::duplex(1 << 20);
    let server = serve_body(server_io, vec![b'x'; 5000]);
    let mut input = http2::PREFACE.to_vec();
    input.extend(initial_window(1000));
    input.extend(get_request());
    client.write_all(&input).await.expect("write");

    let mut reader = FrameReader::default();
    reader.until(&mut client, |r| r.data_len() == 1000).await;
    assert!(reader.is_quiet(&mut client).await, "{:?}", reader.frames);

    // WINDOW_UPDATE for the stream: 500 more bytes, in one DATA frame.
    let update = raw_frame(0x8, 0, 1, &500u32.to_be_bytes());
    client.write_all(&update).await.expect("write");
    reader.until(&mut client, |r| r.data_len() == 1500).await;
    assert!(reader.is_quiet(&mut client).await, "{:?}", reader.frames);

    // Another stream's window does not count, and a PING is answered while the body waits.
    let mut other = raw_frame(0x8, 0, 3, &9999u32.to_be_bytes());
    other.extend(raw_frame(0x6, 0, 0, b"12345678"));
    client.write_all(&other).await.expect("write");
    reader.until(&mut client, |r| r.has(0x6, 0x1)).await;
    assert!(reader.is_quiet(&mut client).await, "{:?}", reader.frames);
    assert_eq!(reader.data_len(), 1500);

    // A new INITIAL_WINDOW_SIZE moves the window by the difference: 4000 - 1000 more bytes,
    // of which 1500 are used. It is acknowledged, a second SETTINGS ACK.
    client
        .write_all(&initial_window(4000))
        .await
        .expect("write");
    reader.until(&mut client, |r| r.data_len() == 4500).await;
    assert!(reader.is_quiet(&mut client).await, "{:?}", reader.frames);
    let acks = reader.frames.iter().filter(|f| (f.0, f.1) == (0x4, 0x1));
    assert_eq!(acks.count(), 2, "{:?}", reader.frames);

    client
        .write_all(&initial_window(100_000))
        .await
        .expect("write");
    reader.until(&mut client, |r| r.has(0x7, 0)).await;
    assert_eq!(reader.data_len(), 5000);
    let [.., end, goaway] = reader.frames.as_slice() else {
        panic!("{:?}", reader.frames)
    };
    assert_eq!(end, &(0x0, 0x1, 1, vec![]), "an empty DATA with END_STREAM");
    assert_eq!(
        goaway,
        &(0x7, 0, 0, vec![0, 0, 0, 1, 0, 0, 0, 0]),
        "GOAWAY: last stream 1, NO_ERROR"
    );
    server.await.expect("join").expect("serve");
}

#[tokio::test]
async fn the_body_waits_for_the_connection_window() {
    use tokio::io::AsyncWriteExt as _;
    let (mut client, server_io) = tokio::io::duplex(1 << 20);
    let server = serve_body(server_io, vec![b'x'; 70_000]);
    let mut input = http2::PREFACE.to_vec();
    // A large stream window, as browsers set; the connection's stays at its 65,535 bytes.
    input.extend(initial_window(6_291_456));
    input.extend(get_request());
    client.write_all(&input).await.expect("write");

    let mut reader = FrameReader::default();
    reader.until(&mut client, |r| r.data_len() == 65_535).await;
    assert!(reader.is_quiet(&mut client).await);

    let update = raw_frame(0x8, 0, 0, &1_000_000u32.to_be_bytes());
    client.write_all(&update).await.expect("write");
    reader.until(&mut client, |r| r.has(0x7, 0)).await;
    assert_eq!(reader.data_len(), 70_000);
    server.await.expect("join").expect("serve");
}

#[tokio::test]
async fn a_window_set_before_the_request_ends_takes_the_body_in_one_go() {
    use tokio::io::AsyncWriteExt as _;
    let (mut client, server_io) = tokio::io::duplex(1 << 20);
    let server = serve_body(server_io, vec![b'x'; 300_000]);
    // What Chrome sends: a 6 MiB stream window and 15 MiB more for the connection.
    let mut input = http2::PREFACE.to_vec();
    input.extend(initial_window(6_291_456));
    input.extend(raw_frame(0x8, 0, 0, &15_663_105u32.to_be_bytes()));
    input.extend(get_request());
    client.write_all(&input).await.expect("write");
    let mut reader = FrameReader::default();
    reader.until(&mut client, |r| r.has(0x7, 0)).await;
    assert_eq!(reader.data_len(), 300_000);
    server.await.expect("join").expect("serve");
}

#[tokio::test]
async fn rst_stream_ends_a_waiting_response() {
    use tokio::io::AsyncWriteExt as _;
    let (mut client, server_io) = tokio::io::duplex(1 << 20);
    let server = serve_body(server_io, vec![b'x'; 5000]);
    let mut input = http2::PREFACE.to_vec();
    input.extend(initial_window(1000));
    input.extend(get_request());
    client.write_all(&input).await.expect("write");
    let mut reader = FrameReader::default();
    reader.until(&mut client, |r| r.data_len() == 1000).await;

    // RST_STREAM on stream 1 with CANCEL.
    let cancel = raw_frame(0x3, 0, 1, &8u32.to_be_bytes());
    client.write_all(&cancel).await.expect("write");
    reader.until(&mut client, |r| r.has(0x7, 0)).await;
    assert_eq!(
        reader.data_len(),
        1000,
        "no DATA on a stream the client reset"
    );
    assert!(!reader.has(0x0, 0x1), "{:?}", reader.frames);
    server.await.expect("join").expect("serve");
}

#[tokio::test]
async fn settings_and_ping_are_acknowledged_before_the_request_arrives() {
    use tokio::io::AsyncWriteExt as _;
    let (mut client, server_io) = tokio::io::duplex(1 << 16);
    let server = serve_body(server_io, b"body".to_vec());
    let mut input = http2::PREFACE.to_vec();
    input.extend(raw_frame(0x4, 0, 0, &[]));
    input.extend(raw_frame(0x6, 0, 0, b"pingdata"));
    client.write_all(&input).await.expect("write");

    // RFC 9113 section 6.5.3: "MUST immediately emit a SETTINGS frame with the ACK flag set";
    // section 6.7: a PING is answered with higher priority than any other frame.
    let mut reader = FrameReader::default();
    reader.until(&mut client, |r| r.has(0x6, 0x1)).await;
    let kinds: Vec<(u8, u8)> = reader.frames.iter().map(|f| (f.0, f.1)).collect();
    assert_eq!(
        kinds,
        [(0x4, 0), (0x4, 0x1), (0x6, 0x1)],
        "SETTINGS, SETTINGS ACK, PING ACK"
    );
    assert_eq!(reader.frames[2].3, b"pingdata");

    client.write_all(&get_request()).await.expect("write");
    reader.until(&mut client, |r| r.has(0x7, 0)).await;
    let acks = reader.frames.iter().filter(|f| f.1 == 0x1 && f.0 != 0x0);
    assert_eq!(
        acks.count(),
        2,
        "each is acknowledged once: {:?}",
        reader.frames
    );
    server.await.expect("join").expect("serve");
}

/// Runs `serve` over `input` followed by the client's end of stream, and returns its result
/// and the frames it wrote.
async fn exchange(
    input: Vec<u8>,
) -> (
    Result<http2::Http2Request, http2::ServeError>,
    Vec<(u8, u8, u32, Vec<u8>)>,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let (mut client, server_io) = tokio::io::duplex(1 << 20);
    let server = serve_body(server_io, b"body".to_vec());
    client.write_all(&input).await.expect("write");
    client.shutdown().await.expect("shutdown");
    let mut output = Vec::new();
    client.read_to_end(&mut output).await.expect("read");
    (server.await.expect("join"), frames_of(&output))
}

/// The payload of a GOAWAY frame.
fn goaway(last_stream: u32, code: u32, debug: &str) -> Vec<u8> {
    let mut payload = last_stream.to_be_bytes().to_vec();
    payload.extend(code.to_be_bytes());
    payload.extend(debug.as_bytes());
    payload
}

#[tokio::test]
async fn a_protocol_error_gets_goaway_with_its_code() {
    // POST / https on stream 1 (static table entries 3, 7 and 4), then 80 KB of body.
    let mut over_the_limit = raw_frame(0x1, 0x4, 1, &[0x83, 0x87, 0x84]);
    over_the_limit.extend(raw_frame(0x0, 0, 1, &[0; 16_000]).repeat(5));
    // The name, the client's frames, and the last stream, code and debug data of the GOAWAY.
    // The stream is the client's request when it sent HEADERS, which then gets RST_STREAM.
    let cases: [(&str, Vec<u8>, u32, u32, &str); 6] = [
        (
            "PROTOCOL_ERROR",
            raw_frame(0x8, 0, 0, &[0; 4]),
            0,
            0x1,
            "invalid frame: WINDOW_UPDATE with zero increment",
        ),
        (
            "FLOW_CONTROL_ERROR",
            initial_window(0x8000_0000),
            0,
            0x3,
            "invalid frame: INITIAL_WINDOW_SIZE too large",
        ),
        (
            "FRAME_SIZE_ERROR",
            raw_frame(0x4, 0, 0, &[0; 5]),
            0,
            0x6,
            "invalid frame: SETTINGS length is not a multiple of 6",
        ),
        (
            "COMPRESSION_ERROR",
            // Index 62 of a dynamic table that has no entries.
            raw_frame(0x1, 0x5, 1, &[0xbe]),
            1,
            0x9,
            "hpack decoding failed",
        ),
        (
            "ENHANCE_YOUR_CALM for a request over 64 KiB",
            over_the_limit,
            1,
            0xb,
            "input exceeds the size limit",
        ),
        (
            "ENHANCE_YOUR_CALM for too many frames",
            raw_frame(0x2, 0, 3, &[0, 0, 0, 0, 15]).repeat(257),
            3,
            0xb,
            "more than 256 frames before the request",
        ),
    ];
    for (name, frames, last_stream, code, debug) in cases {
        let mut input = http2::PREFACE.to_vec();
        input.extend(frames);
        let (result, output) = exchange(input).await;
        assert!(
            matches!(result, Err(http2::ServeError::Protocol(_))),
            "{name}: {result:?}"
        );
        let [first, .., last] = output.as_slice() else {
            panic!("{name}: {output:?}")
        };
        // The request is reset with the same code, which is the error curl and the `h2`
        // crate report. Only the cases with a HEADERS frame have a request.
        let has_request = matches!(code, 0x9) || name.contains("64 KiB");
        let resets: Vec<_> = output.iter().filter(|frame| frame.0 == 0x3).collect();
        if has_request {
            assert_eq!(
                resets,
                [&(0x3, 0, 1, code.to_be_bytes().to_vec())],
                "{name}"
            );
        } else {
            assert_eq!(resets, [] as [&(u8, u8, u32, Vec<u8>); 0], "{name}");
        }
        // RFC 9113 section 3.4: the server's first frame is SETTINGS, also before GOAWAY.
        assert_eq!((first.0, first.1), (0x4, 0), "{name}");
        // Section 5.4.1: GOAWAY with the last stream received and the error code. Naming the
        // request's stream keeps a client from sending the same request again (section 6.8).
        assert_eq!(
            last,
            &(0x7, 0, 0, goaway(last_stream, code, debug)),
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_protocol_error_while_the_body_waits_names_the_answered_stream() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let (mut client, server_io) = tokio::io::duplex(1 << 20);
    let server = serve_body(server_io, vec![b'x'; 5000]);
    let mut input = http2::PREFACE.to_vec();
    input.extend(initial_window(1000));
    input.extend(get_request());
    // A frame over the 16,384 bytes of SETTINGS_MAX_FRAME_SIZE, which the server keeps.
    input.extend(raw_frame(0x0, 0, 3, &vec![0; 16_385]));
    client.write_all(&input).await.expect("write");
    client.shutdown().await.expect("shutdown");
    let mut output = Vec::new();
    client.read_to_end(&mut output).await.expect("read");
    let frames = frames_of(&output);
    let [.., reset, last] = frames.as_slice() else {
        panic!("{frames:?}")
    };
    assert_eq!(reset, &(0x3, 0, 1, vec![0, 0, 0, 6]), "RST_STREAM");
    assert_eq!(
        last,
        &(
            0x7,
            0,
            0,
            goaway(1, 0x6, "invalid frame: frame over SETTINGS_MAX_FRAME_SIZE")
        )
    );
    assert!(matches!(
        server.await.expect("join"),
        Err(http2::ServeError::Protocol(http2::Error::FrameSize(_)))
    ));
}

#[tokio::test]
async fn a_request_that_ends_without_headers_gets_goaway() {
    let mut input = http2::PREFACE.to_vec();
    input.extend(raw_frame(0x0, 0x1, 1, b"data"));
    let (result, output) = exchange(input).await;
    assert_eq!(result.expect("the frames are still reported").stream_id, 0);
    assert_eq!(
        output.last(),
        Some(&(
            0x7,
            0,
            0,
            goaway(
                1,
                0x1,
                "invalid frame: END_STREAM on a stream without HEADERS"
            )
        ))
    );
    assert!(
        output.iter().all(|(kind, ..)| !matches!(kind, 0x1 | 0x3)),
        "no response, and no RST_STREAM for a stream that was never opened: {output:?}"
    );
}

#[tokio::test]
async fn h2_client_is_told_why_a_large_upload_was_refused() {
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    let server = serve_body(server_io, b"body".to_vec());
    let (mut sender, connection) = h2::client::handshake(client_io).await.expect("handshake");
    tokio::spawn(connection);
    let request = http::Request::post("https://example.test/")
        .body(())
        .expect("request");
    let (response, mut body) = sender.send_request(request, false).expect("send");
    // More than the 64 KiB of input the server reads for one request.
    body.send_data(bytes::Bytes::from(vec![0; 100_000]), true)
        .expect("queue the body");
    let error = response.await.expect_err("the request is refused");
    assert_eq!(
        error.reason(),
        Some(h2::Reason::ENHANCE_YOUR_CALM),
        "{error:?}"
    );
    assert!(matches!(
        server.await.expect("join"),
        Err(http2::ServeError::Protocol(http2::Error::TooLarge))
    ));
}
