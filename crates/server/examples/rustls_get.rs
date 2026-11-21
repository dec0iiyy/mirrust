//! Fetches a path from a mirror over HTTP/1.1 with a stock rustls client and prints the body.
//!
//! The certificate is not verified, so this works against the self-signed certificate. The
//! ClientHello is what rustls sends by default; the rustls entries of `crates/fingerprint/data/clients.jsonl`
//! were captured with it.
//!
//! ```console
//! $ cargo run -p server --example rustls_get -- 127.0.0.1:8443 mirror.test /api/all http/1.1
//! ```
//!
//! Arguments: socket address, server name for SNI, path, then any ALPN protocols to offer.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{Context, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

/// Accepts any certificate. Signatures are still checked with the provider's algorithms, so the
/// `signature_algorithms` extension is the one a verifying rustls client sends.
#[derive(Debug)]
struct AcceptAnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(addr), Some(name), Some(path)) = (args.next(), args.next(), args.next()) else {
        bail!("usage: rustls_get ADDR SERVER_NAME PATH [ALPN...]");
    };

    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .context("default protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
        .with_no_client_auth();
    config.alpn_protocols = args.map(String::into_bytes).collect();

    let server_name = ServerName::try_from(name.clone()).context("server name")?;
    let conn = ClientConnection::new(Arc::new(config), server_name).context("client connection")?;
    let socket = TcpStream::connect(&addr).with_context(|| format!("connecting to {addr}"))?;
    let mut stream = StreamOwned::new(conn, socket);

    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {name}\r\nUser-Agent: rustls-get\r\nConnection: close\r\n\r\n"
    )
    .context("sending the request")?;

    let mut response = Vec::new();
    // The server closes the socket after one response; that end of stream is not an error
    // once the response has arrived.
    if let Err(error) = stream.read_to_end(&mut response)
        && response.is_empty()
    {
        return Err(error).context("reading the response");
    }
    let text = String::from_utf8_lossy(&response);
    let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    print!("{body}");
    Ok(())
}
