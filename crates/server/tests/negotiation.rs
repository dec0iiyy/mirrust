//! `/` answers with the text report or the HTML page by `Accept` and `?format=`, the same on
//! HTTP/1.1 and HTTP/2; `/text` is always text and `/api/*` is always JSON.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use server::{Config, self_signed_cert, serve, tls_config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const BROWSER: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

#[derive(Debug, Clone, Copy)]
enum Protocol {
    Http1,
    Http2,
}

const PROTOCOLS: [Protocol; 2] = [Protocol::Http1, Protocol::Http2];

/// A response: status, header names lowercased, and the body as text.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn is_text(&self) -> bool {
        self.header("content-type") == Some("text/plain; charset=utf-8")
            && self.body.starts_with("mirrust  (")
    }

    fn is_page(&self) -> bool {
        self.header("content-type") == Some("text/html; charset=utf-8")
            && self.body.starts_with("<!doctype html>")
    }
}

async fn start() -> (SocketAddr, RootCertStore) {
    let (certs, key) = self_signed_cert().expect("self-signed cert");
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).expect("cert is a usable root");
    let tls = Arc::new(tls_config(certs, key).expect("tls config"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let config = Config {
        h3_port: Some(addr.port()),
        ..Config::default()
    };
    tokio::spawn(serve(listener, tls, Arc::new(config)));
    (addr, roots)
}

async fn connect(
    addr: SocketAddr,
    roots: RootCertStore,
    alpn: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    let socket = TcpStream::connect(addr).await.expect("connect");
    let name = ServerName::try_from("localhost").expect("valid name");
    TlsConnector::from(Arc::new(config))
        .connect(name, socket)
        .await
        .expect("TLS handshake")
}

/// `GET path` with an `Accept` header when `accept` is given.
async fn fetch(
    protocol: Protocol,
    addr: SocketAddr,
    roots: RootCertStore,
    path: &str,
    accept: Option<&str>,
) -> Answer {
    match protocol {
        Protocol::Http1 => fetch_http1(addr, roots, path, accept).await,
        Protocol::Http2 => fetch_http2(addr, roots, path, accept).await,
    }
}

async fn fetch_http1(
    addr: SocketAddr,
    roots: RootCertStore,
    path: &str,
    accept: Option<&str>,
) -> Answer {
    let mut tls = connect(addr, roots, b"http/1.1").await;
    let accept = accept.map_or_else(String::new, |accept| format!("Accept: {accept}\r\n"));
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{accept}\r\n");
    tls.write_all(request.as_bytes()).await.expect("send");
    let mut response = Vec::new();
    // The server closes after one response; a missing close_notify is not this test's concern.
    let _ = tls.read_to_end(&mut response).await;
    let response = String::from_utf8(response).expect("UTF-8 response");
    let (head, body) = response.split_once("\r\n\r\n").expect("header block");
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status line");
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok())
        .expect("Content-Length");
    Answer {
        status,
        headers,
        body: body[..length].to_owned(),
    }
}

async fn fetch_http2(
    addr: SocketAddr,
    roots: RootCertStore,
    path: &str,
    accept: Option<&str>,
) -> Answer {
    let tls = connect(addr, roots, b"h2").await;
    let (mut sender, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(connection);
    let mut request = http::Request::get(format!("https://localhost{path}"));
    if let Some(accept) = accept {
        request = request.header("accept", accept);
    }
    let (response, _) = sender
        .send_request(request.body(()).expect("request"), true)
        .expect("send");
    let response = response.await.expect("response");
    let status = response.status().as_u16();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().expect("ASCII value").to_owned(),
            )
        })
        .collect();
    let mut stream = response.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.expect("body chunk");
        stream
            .flow_control()
            .release_capacity(chunk.len())
            .expect("release capacity");
        body.extend_from_slice(&chunk);
    }
    Answer {
        status,
        headers,
        body: String::from_utf8(body).expect("UTF-8 body"),
    }
}

#[tokio::test]
async fn a_client_that_does_not_ask_for_html_gets_the_text_report() {
    for protocol in PROTOCOLS {
        // curl sends `*/*`; a script may send nothing or something else.
        for accept in [Some("*/*"), None, Some("application/json")] {
            let (addr, roots) = start().await;
            let answer = fetch(protocol, addr, roots, "/", accept).await;
            let what = format!("{protocol:?} {accept:?}");
            assert_eq!(answer.status, 200, "{what}");
            assert!(answer.is_text(), "{what}: {}", answer.body);
            assert!(answer.body.contains("\nAUDIT  "), "{what}");
            assert!(answer.body.contains("\nFINGERPRINTS ---"), "{what}");
            assert!(answer.body.contains("\nTLS ---"), "{what}");
            assert!(answer.body.ends_with("page: /?format=html\n"), "{what}");
            assert_eq!(answer.header("vary"), Some("Accept"), "{what}");
            assert_eq!(answer.header("cache-control"), Some("no-store"), "{what}");
        }
    }
}

#[tokio::test]
async fn a_browser_gets_the_page() {
    for protocol in PROTOCOLS {
        let (addr, roots) = start().await;
        let answer = fetch(protocol, addr, roots, "/", Some(BROWSER)).await;
        assert!(answer.is_page(), "{protocol:?}: {}", answer.body);
        assert!(!answer.body.contains("null/*DATA*/"), "report not inlined");
        assert_eq!(answer.header("vary"), Some("Accept"), "{protocol:?}");
    }
}

#[tokio::test]
async fn the_query_overrides_accept() {
    let cases = [
        ("/?format=text", BROWSER, true),
        ("/?format=html", "*/*", false),
        ("/?format=HTML&x=1", "*/*", false),
        ("/?x=1&format=text", BROWSER, true),
        // An unknown format falls back to `Accept`.
        ("/?format=json", BROWSER, false),
        ("/?format=json", "*/*", true),
    ];
    for protocol in PROTOCOLS {
        for (path, accept, text) in cases {
            let (addr, roots) = start().await;
            let answer = fetch(protocol, addr, roots, path, Some(accept)).await;
            let what = format!("{protocol:?} {path} {accept}");
            assert_eq!(answer.is_text(), text, "{what}");
            assert_eq!(answer.is_page(), !text, "{what}");
            assert_eq!(answer.header("vary"), Some("Accept"), "{what}");
        }
    }
}

#[tokio::test]
async fn text_is_always_text() {
    for protocol in PROTOCOLS {
        for accept in [Some(BROWSER), Some("*/*"), None] {
            let (addr, roots) = start().await;
            let answer = fetch(protocol, addr, roots, "/text", accept).await;
            let what = format!("{protocol:?} {accept:?}");
            assert!(answer.is_text(), "{what}: {}", answer.body);
            assert_eq!(answer.header("vary"), Some("Accept"), "{what}");
        }
    }
}

#[tokio::test]
async fn colour_is_opt_in() {
    for protocol in PROTOCOLS {
        for (path, colour) in [
            ("/text", false),
            ("/", false),
            ("/text?color=0", false),
            ("/text?color=1", true),
            ("/?color=1", true),
            ("/?format=text&color=1", true),
        ] {
            let (addr, roots) = start().await;
            let answer = fetch(protocol, addr, roots, path, Some("*/*")).await;
            assert_eq!(
                answer.body.contains('\x1b'),
                colour,
                "{protocol:?} {path}: {}",
                answer.body
            );
        }
    }
}

#[tokio::test]
async fn the_text_report_is_ascii_and_fits_78_columns() {
    for protocol in PROTOCOLS {
        let (addr, roots) = start().await;
        let answer = fetch(protocol, addr, roots, "/text", None).await;
        assert!(answer.body.is_ascii(), "{protocol:?}");
        for line in answer.body.lines() {
            assert!(line.len() <= 78, "{protocol:?}: {line}");
        }
        let version = match protocol {
            Protocol::Http1 => "(HTTP/1.1, TLS 1.3, 127.0.0.1:",
            Protocol::Http2 => "(h2, TLS 1.3, 127.0.0.1:",
        };
        assert!(answer.body.contains(version), "{}", answer.body);
        // Only the HTTP/2 request has an Akamai fingerprint.
        assert_eq!(
            answer.body.contains("\n  akamai  "),
            matches!(protocol, Protocol::Http2)
        );
    }
}

#[tokio::test]
async fn the_json_api_ignores_accept() {
    for protocol in PROTOCOLS {
        for accept in [Some(BROWSER), Some("*/*"), Some("text/plain"), None] {
            let (addr, roots) = start().await;
            let answer = fetch(protocol, addr, roots, "/api/clean", accept).await;
            let what = format!("{protocol:?} {accept:?}");
            assert_eq!(answer.status, 200, "{what}");
            assert_eq!(
                answer.header("content-type"),
                Some("application/json; charset=utf-8"),
                "{what}"
            );
            let json: Value = serde_json::from_str(&answer.body).expect("JSON body");
            assert!(
                json["ja4"].is_string() && json["audit"]["score"].is_u64(),
                "{what}"
            );
            assert!(answer.header("vary").is_some(), "{what}");
        }
    }
}

#[tokio::test]
async fn unknown_paths_keep_the_html_404_page() {
    for protocol in PROTOCOLS {
        for accept in [Some("*/*"), Some(BROWSER)] {
            let (addr, roots) = start().await;
            let answer = fetch(protocol, addr, roots, "/nope", accept).await;
            assert_eq!(answer.status, 404, "{protocol:?}");
            assert!(answer.is_page(), "{protocol:?}");
            assert!(answer.body.contains("Page not found"));
        }
    }
}
