//! `serve` against a real HTTP/2 client (the `h2` crate) over an in-memory stream.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
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
async fn garbage_is_an_error_not_a_panic() {
    use tokio::io::AsyncWriteExt as _;
    let (mut client_io, mut server_io) = tokio::io::duplex(1 << 16);
    client_io
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("write");
    let result = serve(&mut server_io, &[], Response::default(), |_| {
        Response::default()
    })
    .await;
    assert!(matches!(
        result,
        Err(http2::ServeError::Protocol(http2::Error::BadPreface))
    ));
}
