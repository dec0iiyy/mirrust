//! The connection limit: with every slot taken, new TCP connections are closed at once and new
//! QUIC connections are refused; a freed slot is usable again.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use server::{Config, ConnectionLimit, self_signed_cert, serve, serve_h3, tls_config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

/// Far below the server's 15 s connection timeout, so an admitted connection that is merely
/// left waiting cannot pass for a refused one.
const SOON: Duration = Duration::from_secs(5);

/// Starts TCP and HTTP/3 listeners on one port, sharing a limit of one connection.
async fn start() -> (SocketAddr, RootCertStore) {
    let (certs, key) = self_signed_cert().expect("self-signed cert");
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).expect("cert is a usable root");
    let tls = Arc::new(tls_config(certs, key).expect("tls config"));

    // The same port number must be free over UDP too, and another test process may hold it:
    // try a few ports.
    let mut bound = None;
    for _ in 0..50 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        if let Ok(udp) = std::net::UdpSocket::bind(addr) {
            bound = Some((listener, udp, addr));
            break;
        }
    }
    let (listener, udp, addr) = bound.expect("a port that is free over TCP and UDP");
    let config = Arc::new(Config {
        connections: ConnectionLimit::new(1),
        ..Config::default()
    });
    tokio::spawn(serve(listener, Arc::clone(&tls), Arc::clone(&config)));
    tokio::spawn(serve_h3(udp, tls, config));
    (addr, roots)
}

/// Opens a TCP connection that sends nothing and waits until the server holds the slot for it:
/// the next connection is then turned away.
async fn occupy_the_slot(addr: SocketAddr) -> TcpStream {
    let holder = TcpStream::connect(addr).await.expect("connect");
    assert!(closed_at_once(addr).await, "the only slot is taken");
    holder
}

/// Whether the server closes a new TCP connection without sending anything.
async fn closed_at_once(addr: SocketAddr) -> bool {
    let mut socket = TcpStream::connect(addr).await.expect("connect");
    let read = tokio::time::timeout(SOON, socket.read(&mut [0; 16])).await;
    // A close is an end of stream, or a reset when it overtakes the client's ACK.
    matches!(read, Ok(Ok(0) | Err(_)))
}

/// One HTTP/1.1 request; `None` when the connection was closed before the response.
async fn get_http1(addr: SocketAddr, roots: RootCertStore) -> Option<String> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let socket = TcpStream::connect(addr).await.ok()?;
    let name = ServerName::try_from("localhost").expect("valid name");
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(name, socket)
        .await
        .ok()?;
    tls.write_all(b"GET /api/clean HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .ok()?;
    let mut response = Vec::new();
    // The server closes after one response; a missing close_notify is not this test's concern.
    let _ = tls.read_to_end(&mut response).await;
    String::from_utf8(response)
        .ok()
        .filter(|text| !text.is_empty())
}

#[tokio::test]
async fn tcp_connections_over_the_limit_are_closed_and_a_freed_slot_is_reused() {
    let (addr, roots) = start().await;
    let holder = occupy_the_slot(addr).await;
    assert!(closed_at_once(addr).await, "still taken");

    // The slot is free once the server has seen the holder go away.
    drop(holder);
    let response = tokio::time::timeout(SOON, async {
        loop {
            if let Some(response) = get_http1(addr, roots.clone()).await {
                return response;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a request is served after the slot is freed");
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
}

#[tokio::test]
async fn quic_connections_over_the_limit_are_refused() {
    let (addr, roots) = start().await;
    let _holder = occupy_the_slot(addr).await;

    let mut tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicClientConfig::try_from(tls).expect("QUIC-capable client config");
    let mut endpoint =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connecting = endpoint.connect(addr, "localhost").expect("connect");
    let error = tokio::time::timeout(SOON, connecting)
        .await
        .expect("the server answers")
        .expect_err("the connection is refused");
    let quinn::ConnectionError::ConnectionClosed(close) = &error else {
        panic!("expected the server's close, got {error}");
    };
    assert_eq!(
        close.error_code,
        quinn::TransportErrorCode::CONNECTION_REFUSED,
        "{error}"
    );
}
