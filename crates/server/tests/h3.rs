//! End to end over HTTP/3: a quinn + h3 client against `serve_h3` on the TCP listener's port.

use std::future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Buf;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::RootCertStore;
use serde_json::Value;
use server::{Config, self_signed_cert, serve, serve_h3, tls_config};
use tokio::net::TcpListener;

/// Starts TCP and HTTP/3 listeners on one port; returns it and the certificate as a root.
async fn start() -> (SocketAddr, RootCertStore) {
    let (certs, key) = self_signed_cert().expect("self-signed cert");
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).expect("cert is a usable root");
    let tls = Arc::new(tls_config(certs, key).expect("tls config"));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let udp = std::net::UdpSocket::bind(addr).expect("bind the same port over UDP");
    let config = Arc::new(Config {
        h3_port: Some(addr.port()),
        ..Config::default()
    });
    tokio::spawn(serve(listener, Arc::clone(&tls), Arc::clone(&config)));
    tokio::spawn(serve_h3(udp, tls, config));
    (addr, roots)
}

/// Opens a QUIC connection with ALPN `h3`; the endpoint must outlive the connection.
async fn connect(addr: SocketAddr, roots: RootCertStore) -> (quinn::Endpoint, quinn::Connection) {
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicClientConfig::try_from(tls).expect("QUIC-capable client config");
    let mut endpoint =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connection = endpoint
        .connect(addr, "localhost")
        .expect("connect")
        .await
        .expect("QUIC handshake");
    (endpoint, connection)
}

/// Sends `GET path` over HTTP/3 and returns the response body.
async fn get(addr: SocketAddr, roots: RootCertStore, path: &str) -> Vec<u8> {
    get_accepting(addr, roots, path, None).await.1
}

/// Sends `GET path` over HTTP/3, with an `Accept` header when `accept` is given; returns the
/// response headers and body.
async fn get_accepting(
    addr: SocketAddr,
    roots: RootCertStore,
    path: &str,
    accept: Option<&str>,
) -> (http::HeaderMap, Vec<u8>) {
    let (_endpoint, connection) = connect(addr, roots).await;

    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("HTTP/3 setup");
    tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

    let mut request = http::Request::get(format!("https://localhost:{}{path}", addr.port()))
        .header("user-agent", "h3-test/1");
    if let Some(accept) = accept {
        request = request.header("accept", accept);
    }
    let mut stream = sender
        .send_request(request.body(()).expect("request"))
        .await
        .expect("send request");
    stream.finish().await.expect("finish request");
    let response = stream.recv_response().await.expect("response head");
    assert_eq!(response.status(), 200);
    let headers = response.headers().clone();
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["referrer-policy"], "no-referrer");
    assert_eq!(headers["vary"], "Accept");

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.expect("response body") {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    (headers, body)
}

#[tokio::test]
async fn h3_reports_the_quic_client_hello() {
    let (addr, roots) = start().await;
    let body = get(addr, roots, "/api/all").await;
    let json: Value = serde_json::from_slice(&body).expect("JSON body");

    assert_eq!(json["http_version"], "h3");
    assert_eq!(json["method"], "GET");
    assert_eq!(json["user_agent"], "h3-test/1");
    assert_eq!(json["tls"]["tls_version_negotiated"], "772");
    let ja4 = json["tls"]["ja4"].as_str().expect("tls.ja4");
    assert!(ja4.starts_with("q13d"), "QUIC JA4 expected, got {ja4}");
    assert_eq!(&ja4[8..10], "h3", "ALPN h3 in {ja4}");
    let ja4_peet = json["tls"]["ja4_peet"].as_str().expect("tls.ja4_peet");
    assert!(ja4_peet.starts_with('q'), "{ja4_peet}");
}

#[tokio::test]
async fn h3_reports_the_quic_transport_parameters() {
    let (addr, roots) = start().await;
    let body = get(addr, roots, "/api/all").await;
    let json: Value = serde_json::from_slice(&body).expect("JSON body");

    let extensions = json["tls"]["extensions"].as_array().expect("extensions");
    let parameters = extensions
        .iter()
        .find(|extension| extension["name"] == "quic_transport_parameters (57)")
        .and_then(|extension| extension["parameters"].as_array())
        .expect("extension 57 with decoded parameters");
    let value_of = |name: &str| {
        parameters
            .iter()
            .find(|parameter| parameter["name"] == name)
            .map(|parameter| &parameter["value"])
    };
    // quinn's client always sends these two: an integer and a connection id.
    let max_data = value_of("initial_max_data").expect("initial_max_data");
    assert!(max_data.is_u64(), "{max_data}");
    let scid = value_of("initial_source_connection_id").expect("initial_source_connection_id");
    assert!(scid.is_string(), "{scid}");
    for parameter in parameters {
        assert!(parameter["id"].is_u64(), "{parameter}");
    }
}

#[tokio::test]
async fn h3_reports_the_quic_initial() {
    let (addr, roots) = start().await;
    let body = get(addr, roots, "/api/all").await;
    let json: Value = serde_json::from_slice(&body).expect("JSON body");

    let quic = &json["quic"];
    assert_eq!(quic["version"], "0x00000001");
    // quinn's client: a random 20-byte destination id at first, 8-byte ids of its own, no
    // token on a first visit.
    assert_eq!(quic["dcid_length"], 20);
    assert_eq!(quic["scid_length"], 8);
    assert_eq!(quic["token_length"], 0);
    let sizes = quic["initial_datagram_sizes"].as_array().expect("sizes");
    assert_eq!(quic["initial_datagrams"], sizes.len());
    assert_ne!(sizes.len(), 0, "no Initial datagram counted");
    for size in sizes {
        // A client pads datagrams with Initial packets to 1200 bytes or more (RFC 9000 §14.1).
        assert!(size.as_u64().is_some_and(|size| size >= 1200), "{size}");
    }
    let keys: Vec<&String> = json.as_object().expect("object").keys().collect();
    assert_eq!(
        keys,
        [
            "ip",
            "http_version",
            "method",
            "user_agent",
            "tls",
            "quic",
            "http3",
            "tcpip",
            "client",
            "audit"
        ]
    );
}

#[tokio::test]
async fn h3_reports_settings_and_stream_types() {
    let (addr, roots) = start().await;
    let body = get(addr, roots, "/api/all").await;
    let json: Value = serde_json::from_slice(&body).expect("JSON body");
    let http3 = &json["http3"];

    // The control stream is the first stream the `h3` client opens.
    let streams = http3["streams"].as_array().expect("streams");
    assert_eq!(
        streams[0],
        serde_json::json!({ "id": 2, "type": 0, "name": "control" })
    );
    let settings = http3["settings"]
        .as_array()
        .expect("the SETTINGS frame is read before the first request is answered");
    assert_ne!(settings.len(), 0, "the `h3` client sends settings");

    // The fingerprint is the two lists, with reserved ids and types as GREASE.
    let setting_parts: Vec<String> = settings
        .iter()
        .map(|setting| {
            assert!(setting["value"].is_u64(), "{setting}");
            if setting["name"] == "GREASE" {
                "GREASE".to_owned()
            } else {
                format!("{}:{}", setting["id"], setting["value"])
            }
        })
        .collect();
    let stream_parts: Vec<String> = streams
        .iter()
        .map(|stream| {
            if stream["name"] == "GREASE" {
                "GREASE".to_owned()
            } else {
                stream["type"].to_string()
            }
        })
        .collect();
    let fingerprint = http3["fingerprint"].as_str().expect("fingerprint");
    assert_eq!(
        fingerprint,
        format!("{}|{}", setting_parts.join(";"), stream_parts.join(","))
    );
    assert!(fingerprint.ends_with("|0,2,3"), "{fingerprint}");
    let hash = http3["fingerprint_hash"].as_str().expect("hash");
    assert_eq!(hash.len(), 32, "{hash}");
}

/// Sends, as raw HTTP/3, a `GET /api/all` with `extra` header fields of 1000 bytes each, and
/// returns what the server sends back on the request stream. The `h3` client cannot do this: it
/// refuses to send more than the server's SETTINGS allow. The fields are QPACK literals (RFC
/// 9204 §4.5), no dynamic table.
async fn raw_get_with_headers(
    addr: SocketAddr,
    roots: RootCertStore,
    extra: usize,
) -> Result<Vec<u8>, quinn::ReadToEndError> {
    let (_endpoint, connection) = connect(addr, roots).await;
    let mut control = connection.open_uni().await.expect("control stream");
    // Stream type 0 (control) and an empty SETTINGS frame.
    control
        .write_all(&[0x00, 0x04, 0x00])
        .await
        .expect("settings");

    let mut section = vec![0x00, 0x00]; // required insert count 0, base 0
    section.extend([0xd1, 0xd7]); // :method GET, :scheme https
    section.extend([0x50, 9]); // :authority, literal value of 9 bytes
    section.extend(b"localhost");
    section.extend([0x51, 8]); // :path, literal value of 8 bytes
    section.extend(b"/api/all");
    for _ in 0..extra {
        section.extend([0x21, b'x']); // literal name "x"
        section.extend([0x7f, 0xe9, 0x06]); // value of 127 + 873 = 1000 bytes
        section.extend([b'a'; 1000]);
    }
    let mut request = vec![0x01]; // HEADERS
    let length = u32::try_from(section.len()).expect("short section") | 0x8000_0000;
    request.extend(length.to_be_bytes());
    request.extend(section);

    let (mut send, mut recv) = connection.open_bi().await.expect("request stream");
    // The stream's flow-control window is larger than the request, so it goes out whole.
    send.write_all(&request).await.expect("request");
    send.finish().expect("finish");
    tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1 << 20))
        .await
        .expect("the server answers or closes the stream")
}

/// Whether `bytes` contain the report the routes build for `/api/all`.
fn is_report(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes).contains("\"http_version\"")
}

#[tokio::test]
async fn h3_answers_a_request_with_large_headers_under_the_limit() {
    let (addr, roots) = start().await;
    // About 40 KB of headers against a 64 KiB limit.
    let answer = raw_get_with_headers(addr, roots, 40).await;
    assert!(answer.is_ok_and(|bytes| is_report(&bytes)));
}

#[tokio::test]
async fn h3_does_not_answer_a_request_with_oversized_headers_and_keeps_serving() {
    let (addr, roots) = start().await;
    // About 100 KB of headers: more than the limit, less than the stream's receive window.
    let answer = raw_get_with_headers(addr, roots.clone(), 100).await;
    assert!(
        answer.is_err_and(|error| matches!(error, quinn::ReadToEndError::Read(_))),
        "no response, only a closed stream or connection"
    );

    // The server is still up for the next client.
    let body = get(addr, roots, "/api/all").await;
    let json: Value = serde_json::from_slice(&body).expect("JSON body");
    assert_eq!(json["http_version"], "h3");
}

#[tokio::test]
async fn h3_answers_100_requests_per_connection_then_sends_goaway() {
    let (addr, roots) = start().await;
    let (_endpoint, connection) = connect(addr, roots.clone()).await;
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("HTTP/3 setup");
    tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

    let request = || {
        http::Request::get(format!("https://localhost:{}/api/clean", addr.port()))
            .body(())
            .expect("request")
    };
    // `MAX_REQUESTS_PER_CONNECTION` in `h3_handler`.
    for n in 1..=100 {
        let mut stream = sender
            .send_request(request())
            .await
            .unwrap_or_else(|error| panic!("request {n}: {error}"));
        stream.finish().await.expect("finish request");
        let response = stream.recv_response().await.expect("response head");
        assert_eq!(response.status(), 200, "request {n}");
        while stream.recv_data().await.expect("response body").is_some() {}
    }
    let hundred_and_first = async {
        let mut stream = sender.send_request(request()).await?;
        stream.finish().await?;
        stream.recv_response().await?;
        Ok::<_, h3::error::StreamError>(())
    };
    let outcome = tokio::time::timeout(Duration::from_secs(5), hundred_and_first)
        .await
        .expect("the server rejects the request instead of leaving it open");
    assert!(outcome.is_err(), "request 101 was answered");

    // A new connection gets answers again.
    let body = get(addr, roots, "/api/all").await;
    let json: Value = serde_json::from_slice(&body).expect("JSON body");
    assert_eq!(json["http_version"], "h3");
}

#[tokio::test]
async fn h3_negotiates_the_text_report_and_the_page() {
    const BROWSER: &str = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8";
    let cases = [
        ("/", None, true),
        ("/", Some("*/*"), true),
        ("/", Some(BROWSER), false),
        ("/?format=text", Some(BROWSER), true),
        ("/?format=html", Some("*/*"), false),
        ("/text", Some(BROWSER), true),
    ];
    for (path, accept, text) in cases {
        let (addr, roots) = start().await;
        let (headers, body) = get_accepting(addr, roots, path, accept).await;
        let body = String::from_utf8(body).expect("UTF-8 body");
        let what = format!("{path} {accept:?}");
        if text {
            assert_eq!(
                headers["content-type"], "text/plain; charset=utf-8",
                "{what}"
            );
            assert!(
                body.starts_with("mirrust  (h3, TLS 1.3, 127.0.0.1:"),
                "{what}: {body}"
            );
            assert!(body.contains("\nAUDIT  "), "{what}");
            // QUIC JA4 and the HTTP/3 fingerprint instead of an Akamai one.
            assert!(body.contains("\n  ja4        q13d"), "{what}: {body}");
            assert!(body.contains("\n  http3      "), "{what}: {body}");
            assert!(!body.contains("akamai"), "{what}");
            assert!(
                body.is_ascii() && body.lines().all(|line| line.len() <= 78),
                "{what}"
            );
        } else {
            assert_eq!(
                headers["content-type"], "text/html; charset=utf-8",
                "{what}"
            );
            assert!(body.starts_with("<!doctype html>"), "{what}");
        }
    }
}

#[tokio::test]
async fn h3_json_api_ignores_accept() {
    let (addr, roots) = start().await;
    let (headers, body) = get_accepting(addr, roots, "/api/clean", Some("text/html")).await;
    assert_eq!(headers["content-type"], "application/json; charset=utf-8");
    let json: Value = serde_json::from_slice(&body).expect("JSON body");
    assert!(json["ja4"].as_str().is_some_and(|ja4| ja4.starts_with('q')));
}
