//! End to end: a rustls client against the server on an ephemeral port.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use fingerprint::{ClientHello, Ja3, Ja4, Ja4Peet, PeetPrint, Transport};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::Value;
use server::{Config, self_signed_cert, serve, tls_config};
use tokio::runtime::Runtime;

/// Starts the server; the runtime must outlive the requests.
fn start() -> (Runtime, SocketAddr, RootCertStore) {
    let (certs, key) = self_signed_cert().expect("self-signed cert");
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).expect("cert is a usable root");
    let tls = Arc::new(tls_config(certs, key).expect("tls config"));

    let runtime = Runtime::new().expect("tokio runtime");
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let config = Config {
        h3_port: Some(addr.port()),
        ..Config::default()
    };
    runtime.spawn(serve(listener, tls, Arc::new(config)));
    (runtime, addr, roots)
}

/// Sends `path` over HTTP/1.1; returns the ClientHello message the client sent and the body.
fn get(addr: SocketAddr, roots: RootCertStore, path: &str) -> (Vec<u8>, String) {
    get_with_status(addr, roots, path, "200 OK")
}

/// Like [`get`], expecting `status` (code and reason) in the status line.
fn get_with_status(
    addr: SocketAddr,
    roots: RootCertStore,
    path: &str,
    status: &str,
) -> (Vec<u8>, String) {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = ServerName::try_from("localhost").expect("valid name");
    let mut conn = ClientConnection::new(Arc::new(config), name).expect("client connection");

    // The ClientHello is queued as soon as the connection exists; capture it on its way out.
    let mut first_flight = Vec::new();
    conn.write_tls(&mut first_flight).expect("first flight");
    let hello = handshake_message(&first_flight);

    let mut socket = TcpStream::connect(addr).expect("connect");
    socket.write_all(&first_flight).expect("send ClientHello");
    let mut tls = StreamOwned::new(conn, socket);
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: it/1\r\n\r\n");
    tls.write_all(request.as_bytes()).expect("send request");
    let mut response = Vec::new();
    // The server closes after one response; a missing close_notify is not this test's concern.
    let _ = tls.read_to_end(&mut response);

    let response = String::from_utf8(response).expect("UTF-8 response");
    let (head, body) = response.split_once("\r\n\r\n").expect("header block");
    assert!(
        head.starts_with(&format!("HTTP/1.1 {status}\r\n")),
        "{head}"
    );
    let alt_svc = format!("\r\nAlt-Svc: h3=\":{}\"; ma=86400\r\n", addr.port());
    assert!(head.contains(&alt_svc), "{head}");
    for header in [
        "Cache-Control: no-store",
        "X-Content-Type-Options: nosniff",
        "Referrer-Policy: no-referrer",
    ] {
        assert!(head.contains(&format!("\r\n{header}\r\n")), "{head}");
    }
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .expect("Content-Length")
        .parse()
        .expect("numeric Content-Length");
    assert_eq!(
        &body[length..],
        "\r\n\r\n",
        "two CRLFs follow the body, as on tls.peet.ws"
    );
    (hello, body[..length].to_owned())
}

#[test]
fn unknown_paths_get_the_built_in_404_page() {
    for path in ["/nope", "/explore", "/api/nope?x=<b>"] {
        let (_runtime, addr, roots) = start();
        let (_, body) = get_with_status(addr, roots, path, "404 Not Found");
        assert!(body.starts_with("<!doctype html>"), "{path}: {body}");
        assert!(body.contains("Page not found"), "{path}");
        // The page reads the path from the address bar; the server echoes nothing into it.
        assert!(!body.contains("nope"), "{path}");
    }
}

#[test]
fn root_serves_the_page_with_the_report_inlined() {
    let (_runtime, addr, roots) = start();
    let (_, body) = get(addr, roots, "/");
    assert!(body.starts_with("<!doctype html>"), "{body}");
    assert!(!body.contains("null/*DATA*/"), "report was not inlined");
}

/// The first handshake message in a run of TLS records.
fn handshake_message(records: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    let mut rest = records;
    while rest.len() >= 5 {
        let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        payload.extend_from_slice(&rest[5..5 + len]);
        rest = &rest[5 + len..];
    }
    let len =
        usize::from(payload[1]) << 16 | usize::from(payload[2]) << 8 | usize::from(payload[3]);
    payload.truncate(4 + len);
    payload
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").expect("writing to a String cannot fail");
        out
    })
}

#[test]
fn api_tls_reports_the_fingerprints_of_the_hello_the_client_sent() {
    let (_runtime, addr, roots) = start();
    let (message, body) = get(addr, roots, "/api/tls");
    let json: Value = serde_json::from_str(&body).expect("JSON body");

    let hello = ClientHello::parse_peet(&message);
    let ja3 = Ja3::new(&hello);
    let ja4 = Ja4::new(&ClientHello::parse(&message), Transport::Tcp);
    let ja4_peet = Ja4Peet::new(&hello, 0x0304, Transport::Tcp);
    let peet = PeetPrint::new(&hello);
    let tls = &json["tls"];
    let want = [
        (
            "tls_version_record",
            Value::from(hello.legacy_version.to_string()),
        ),
        ("tls_version_negotiated", "772".into()),
        ("ja3", ja3.text().into()),
        ("ja3_hash", ja3.hash().into()),
        ("ja4", ja4.hashed().into()),
        ("ja4_r", ja4.raw().into()),
        ("ja4_o", ja4.original().into()),
        ("ja4_ro", ja4.raw_original().into()),
        ("ja4_peet", ja4_peet.hashed().into()),
        ("ja4_peet_r", ja4_peet.raw().into()),
        ("peetprint", peet.text().into()),
        ("peetprint_hash", peet.hash().into()),
        ("client_random", hex(&hello.random).into()),
        ("session_id", hex(&hello.session_id).into()),
        ("ciphers", hello.readable_ciphers().into()),
        ("extensions", hello.extension_details()),
    ];
    for (field, value) in want {
        assert_eq!(tls[field], value, "tls.{field}");
    }

    let keys: Vec<&str> = json
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["ip", "http_version", "method", "tls", "tcpip"]);
}

#[test]
fn api_all_reports_http1_headers_in_order() {
    let (_runtime, addr, roots) = start();
    let (_, body) = get(addr, roots, "/api/all?x=1");
    let json: Value = serde_json::from_str(&body).expect("JSON body");
    assert_eq!(json["http_version"], "HTTP/1.1");
    assert_eq!(json["method"], "GET");
    assert_eq!(json["user_agent"], "it/1");
    assert_eq!(
        json["http1"]["headers"],
        serde_json::json!(["Host: localhost", "User-Agent: it/1"])
    );
    assert!(body.starts_with("{\n  \"ip\": "), "{body}");
}

#[test]
fn api_raw_returns_the_hello_as_sent() {
    let (_runtime, addr, roots) = start();
    let (message, body) = get(addr, roots, "/api/raw");
    let json: Value = serde_json::from_str(&body).expect("JSON body");
    assert_eq!(json["raw"], hex(&message));
}
