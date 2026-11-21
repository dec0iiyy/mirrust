//! IPv6: the server on `[::1]` over HTTP/1.1, HTTP/2 and HTTP/3, and IPv4 clients of an IPv6
//! socket, which the kernel hands over as IPv4-mapped addresses (`::ffff:a.b.c.d`).
//!
//! A machine without IPv6 loopback skips these tests with a message instead of failing them.

use std::future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use bytes::Buf;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use server::{Config, keep_syn, self_signed_cert, serve, serve_h3, tls_config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const LINUX_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) Chrome/160.0.0.0";

#[derive(Debug, Clone, Copy)]
enum Protocol {
    Http1,
    Http2,
    Http3,
}

const PROTOCOLS: [Protocol; 3] = [Protocol::Http1, Protocol::Http2, Protocol::Http3];

impl Protocol {
    /// The report's `http_version` for a request over this protocol.
    fn version(self) -> &'static str {
        match self {
            Self::Http1 => "HTTP/1.1",
            Self::Http2 => "h2",
            Self::Http3 => "h3",
        }
    }
}

/// Starts TCP and HTTP/3 listeners on one port of `ip`; `None` when `ip` cannot be bound here.
async fn start(ip: IpAddr) -> Option<(SocketAddr, RootCertStore)> {
    let (certs, key) = self_signed_cert().expect("self-signed cert");
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).expect("cert is a usable root");
    let tls = Arc::new(tls_config(certs, key).expect("tls config"));

    // The same port number must be free over UDP too, and another test process may hold it:
    // try a few ports.
    let mut bound = None;
    for _ in 0..50 {
        let listener = match TcpListener::bind((ip, 0)).await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("skipped: cannot bind {ip} here ({error})");
                return None;
            }
        };
        let addr = listener.local_addr().expect("local addr");
        if let Ok(udp) = std::net::UdpSocket::bind(addr) {
            bound = Some((listener, udp, addr));
            break;
        }
    }
    let (listener, udp, addr) = bound.expect("a port that is free over TCP and UDP");
    // Before anything connects: the kernel keeps only the SYNs that arrive after this.
    keep_syn(&listener);
    let config = Arc::new(Config {
        h3_port: Some(addr.port()),
        ..Config::default()
    });
    tokio::spawn(serve(listener, Arc::clone(&tls), Arc::clone(&config)));
    tokio::spawn(serve_h3(udp, tls, config));
    Some((addr, roots))
}

/// `GET /api/all` to `target` over `protocol` with `user_agent`; returns the report and the
/// client's own address.
async fn fetch(
    protocol: Protocol,
    target: SocketAddr,
    roots: RootCertStore,
    user_agent: &str,
) -> (Value, SocketAddr) {
    let (body, client) = match protocol {
        Protocol::Http1 => fetch_http1(target, roots, user_agent).await,
        Protocol::Http2 => fetch_http2(target, roots, user_agent).await,
        Protocol::Http3 => fetch_http3(target, roots, user_agent).await,
    };
    let report: Value = serde_json::from_slice(&body).expect("JSON body");
    assert_eq!(report["http_version"], protocol.version(), "{report}");
    (report, client)
}

async fn connect_tls(
    target: SocketAddr,
    roots: RootCertStore,
    alpn: &[u8],
) -> (tokio_rustls::client::TlsStream<TcpStream>, SocketAddr) {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    let socket = TcpStream::connect(target).await.expect("connect");
    let client = socket.local_addr().expect("client address");
    let name = ServerName::try_from("localhost").expect("valid name");
    let tls = TlsConnector::from(Arc::new(config))
        .connect(name, socket)
        .await
        .expect("TLS handshake");
    (tls, client)
}

async fn fetch_http1(
    target: SocketAddr,
    roots: RootCertStore,
    user_agent: &str,
) -> (Vec<u8>, SocketAddr) {
    let (mut tls, client) = connect_tls(target, roots, b"http/1.1").await;
    let request =
        format!("GET /api/all HTTP/1.1\r\nHost: localhost\r\nUser-Agent: {user_agent}\r\n\r\n");
    tls.write_all(request.as_bytes()).await.expect("send");
    let mut response = Vec::new();
    // The server closes after one response; a missing close_notify is not this test's concern.
    let _ = tls.read_to_end(&mut response).await;
    let start = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header block")
        + 4;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    (response[start..].to_vec(), client)
}

async fn fetch_http2(
    target: SocketAddr,
    roots: RootCertStore,
    user_agent: &str,
) -> (Vec<u8>, SocketAddr) {
    let (tls, client) = connect_tls(target, roots, b"h2").await;
    let (mut sender, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(connection);
    let request = http::Request::get("https://localhost/api/all")
        .header("user-agent", user_agent)
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    let response = response.await.expect("response");
    assert_eq!(response.status(), 200);
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
    (body, client)
}

async fn fetch_http3(
    target: SocketAddr,
    roots: RootCertStore,
    user_agent: &str,
) -> (Vec<u8>, SocketAddr) {
    let mut tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicClientConfig::try_from(tls).expect("QUIC-capable client config");
    // The address the server will see, and the one the socket binds to. An IPv6 client binds to
    // the unspecified address: quinn makes that socket dual-stack, and Windows refuses that
    // option on a socket bound to `::1` (error 10022). The kernel then picks `::1` as the
    // source for a target on the loopback.
    let (seen, bind): (IpAddr, IpAddr) = if target.is_ipv6() {
        (Ipv6Addr::LOCALHOST.into(), Ipv6Addr::UNSPECIFIED.into())
    } else {
        (Ipv4Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into())
    };
    let mut endpoint = quinn::Endpoint::client((bind, 0).into()).expect("client endpoint");
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let client = SocketAddr::new(seen, endpoint.local_addr().expect("client address").port());
    let connection = endpoint
        .connect(target, "localhost")
        .expect("connect")
        .await
        .expect("QUIC handshake");

    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("HTTP/3 setup");
    tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });
    let request = http::Request::get(format!("https://localhost:{}/api/all", target.port()))
        .header("user-agent", user_agent)
        .body(())
        .expect("request");
    let mut stream = sender.send_request(request).await.expect("send request");
    stream.finish().await.expect("finish request");
    let response = stream.recv_response().await.expect("response head");
    assert_eq!(response.status(), 200);
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.expect("response body") {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    (body, client)
}

fn check<'report>(report: &'report Value, id: &str) -> Option<&'report Value> {
    report["audit"]["checks"]
        .as_array()?
        .iter()
        .find(|check| check["id"] == id)
}

#[tokio::test]
async fn an_ipv6_client_gets_its_reports_over_every_protocol() {
    let Some((addr, roots)) = start(Ipv6Addr::LOCALHOST.into()).await else {
        return;
    };
    for protocol in PROTOCOLS {
        let (report, client) = fetch(protocol, addr, roots.clone(), LINUX_UA).await;
        assert_eq!(
            report["ip"],
            format!("[::1]:{}", client.port()),
            "{protocol:?}"
        );
        let ip: SocketAddr = report["ip"]
            .as_str()
            .and_then(|ip| ip.parse().ok())
            .expect("ip is a socket address");
        assert_eq!(ip, client, "{protocol:?}");

        let tcpip = &report["tcpip"];
        if matches!(protocol, Protocol::Http3) || !cfg!(target_os = "linux") {
            // No TCP SYN over QUIC, and only Linux keeps one.
            assert!(tcpip.get("tcp_syn").is_none(), "{protocol:?}: {tcpip}");
            continue;
        }
        let syn = &tcpip["tcp_syn"];
        assert_eq!(syn["ip_version"], 6, "{protocol:?}: {tcpip}");
        assert_eq!(syn["src_ip"], "::1", "{tcpip}");
        assert_eq!(syn["dst_ip"], "::1", "{tcpip}");
        assert_eq!(syn["src_port"], client.port(), "{tcpip}");
        assert_eq!(syn["dst_port"], addr.port(), "{tcpip}");
        assert!(syn["ttl"].as_u64().is_some_and(|hops| hops > 0), "{syn}");
        assert!(syn["mss"].as_u64().is_some_and(|mss| mss > 0), "{syn}");
        assert!(
            syn.get("ip_id").is_none() && syn.get("df").is_none(),
            "{syn}"
        );
        assert_eq!(syn["payload_len"], 0, "the kernel keeps the headers only");
        assert!(
            tcpip["p0f"]
                .as_str()
                .is_some_and(|p0f| p0f.starts_with("6:")),
            "{tcpip}"
        );
        let tcp_os = check(&report, "tcp_os").expect("tcp_os applies to a Linux User-Agent");
        assert_eq!(tcp_os["status"], "pass", "{tcp_os}");
        let tcp_mss = check(&report, "tcp_mss").expect("tcp_mss applies with a SYN");
        assert_ne!(tcp_mss["status"], "skip", "{tcp_mss}");
    }
}

/// `--listen [::]:443` takes IPv4 connections too where `IPV6_V6ONLY` is off (the Linux and
/// macOS default), and the kernel gives their peers as IPv4-mapped addresses. The listeners
/// are on every interface for the length of the test, as no narrower bind behaves the same:
/// on macOS, quinn answers no QUIC handshake from a socket bound to `::ffff:127.0.0.1`.
#[tokio::test]
async fn an_ipv4_client_of_an_ipv6_socket_is_reported_as_ipv4() {
    let Some((addr, roots)) = start(Ipv6Addr::UNSPECIFIED.into()).await else {
        return;
    };
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, addr.port()));
    if TcpStream::connect(target).await.is_err() {
        eprintln!("skipped: the IPv6 socket takes no IPv4 connection here (IPV6_V6ONLY)");
        return;
    }
    for protocol in PROTOCOLS {
        let (report, client) = fetch(protocol, target, roots.clone(), LINUX_UA).await;
        assert_eq!(
            report["ip"],
            format!("127.0.0.1:{}", client.port()),
            "{protocol:?}"
        );
        if matches!(protocol, Protocol::Http3) || !cfg!(target_os = "linux") {
            continue;
        }
        // The kernel keeps the SYN as it arrived: an IPv4 packet.
        let tcpip = &report["tcpip"];
        assert_eq!(tcpip["tcp_syn"]["ip_version"], 4, "{protocol:?}: {tcpip}");
        assert_eq!(tcpip["tcp_syn"]["src_ip"], "127.0.0.1", "{tcpip}");
        assert!(
            tcpip["p0f"]
                .as_str()
                .is_some_and(|p0f| p0f.starts_with("4:")),
            "{tcpip}"
        );
    }
}
