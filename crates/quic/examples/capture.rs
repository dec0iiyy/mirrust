//! Captures a real client's QUIC Initial on a local UDP port and prints its ClientHello and JA4.
//!
//! ```text
//! cargo run -p quic --example capture              # a quinn client connects to 127.0.0.1:7444
//! cargo run -p quic --example capture -- listen    # wait for another client, e.g. Chrome:
//!   chrome --headless --origin-to-force-quic-on=127.0.0.1:7444 https://127.0.0.1:7444/
//! ```
//!
//! The ClientHello is also written as hex to `client_hello.hex` in the current directory, and the
//! datagrams it came in to `datagrams.hex`, one per line.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fingerprint::{ClientHello, Ja4, Transport};
use quic::InitialAssembler;
use tokio::net::UdpSocket;

const LISTEN: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 7444);

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(LISTEN).await?;
    let listen_only = std::env::args().nth(1).is_some_and(|arg| arg == "listen");
    if !listen_only {
        tokio::spawn(connect_with_quinn());
    }

    let mut assembler = InitialAssembler::new();
    let mut buf = vec![0u8; 65_535];
    let mut datagrams = 0;
    let mut datagram_hex = String::new();
    let initial = loop {
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(60), socket.recv_from(&mut buf)).await??;
        datagrams += 1;
        datagram_hex.push_str(&to_hex(&buf[..len]));
        datagram_hex.push('\n');
        println!("datagram {datagrams}: {len} bytes from {from}");
        match assembler.push(&buf[..len]) {
            Ok(Some(initial)) => break initial,
            Ok(None) => {}
            Err(err) => println!("  skipped: {err}"),
        }
    };

    std::fs::write("client_hello.hex", to_hex(initial.client_hello()))?;
    std::fs::write("datagrams.hex", datagram_hex)?;
    let hello = ClientHello::parse(initial.client_hello());
    let ja4 = Ja4::new(&hello, Transport::Quic);
    println!("version:      {:?}", initial.version());
    println!("dcid:         {:02x?}", initial.dcid());
    println!("scid:         {:02x?}", initial.scid());
    println!("datagrams:    {datagrams}");
    println!("ClientHello:  {} bytes", initial.client_hello().len());
    println!("JA4:          {}", ja4.hashed());
    println!("JA4_r:        {}", ja4.raw());
    Ok(())
}

/// Starts a quinn handshake towards [`LISTEN`]; it never completes, only its Initial matters.
async fn connect_with_quinn() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))?;
    let mut endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let _ = endpoint.connect(LISTEN, "localhost")?.await;
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}
