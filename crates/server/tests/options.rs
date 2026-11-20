//! The answer to `OPTIONS` carries the same headers on HTTP/1.1 and HTTP/2.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use server::{Config, self_signed_cert, serve, tls_config};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;

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

fn client_config(roots: RootCertStore, alpn: &[u8]) -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

type Headers = Vec<(String, String)>;

/// The headers of the answer to `OPTIONS /` over HTTP/1.1, names lowercased and sorted.
fn options_http1(addr: SocketAddr, roots: RootCertStore) -> Headers {
    let name = ServerName::try_from("localhost").expect("valid name");
    let conn = ClientConnection::new(Arc::new(client_config(roots, b"http/1.1")), name)
        .expect("client connection");
    let mut tls = StreamOwned::new(conn, TcpStream::connect(addr).expect("connect"));
    tls.write_all(b"OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("send request");
    let mut response = Vec::new();
    // The server closes after one response; a missing close_notify is not this test's concern.
    let _ = tls.read_to_end(&mut response);
    let response = String::from_utf8(response).expect("UTF-8 response");
    let (head, _) = response.split_once("\r\n\r\n").expect("header block");
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    let mut headers: Headers = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned()))
        .collect();
    headers.sort();
    headers
}

async fn options_http2(addr: SocketAddr, roots: RootCertStore) -> Headers {
    let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let name = ServerName::try_from("localhost").expect("valid name");
    let tls = TlsConnector::from(Arc::new(client_config(roots, b"h2")))
        .connect(name, socket)
        .await
        .expect("TLS handshake");
    let (mut sender, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(connection);
    let request = http::Request::options("https://localhost/")
        .body(())
        .expect("valid request");
    let (response, _) = sender.send_request(request, true).expect("send");
    let response = response.await.expect("response");
    assert_eq!(response.status(), 200);
    let mut headers: Headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().expect("ASCII value").to_owned(),
            )
        })
        .collect();
    headers.sort();
    headers
}

fn value<'h>(headers: &'h Headers, name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

#[tokio::test(flavor = "multi_thread")]
async fn options_has_the_same_headers_on_http1_and_http2() {
    let (addr, roots) = start().await;
    let h1 = {
        let roots = roots.clone();
        tokio::task::spawn_blocking(move || options_http1(addr, roots))
            .await
            .expect("HTTP/1.1 client")
    };
    let h2 = options_http2(addr, roots).await;

    assert_eq!(
        value(&h2, "content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(
        value(&h2, "alt-svc"),
        Some(format!("h3=\":{}\"; ma=86400", addr.port()).as_str())
    );
    assert_eq!(value(&h2, "access-control-allow-origin"), Some("*"));
    assert_eq!(h1, h2, "same header names and values on both protocols");
}
