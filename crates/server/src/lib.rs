//! mirrust: a TLS server that answers each request with the client's own fingerprints,
//! in the same JSON as tls.peet.ws.
//!
//! Each connection is handled in three steps: the ClientHello is read off the socket and
//! fingerprinted, the buffered bytes are replayed into rustls for the handshake, and the
//! negotiated ALPN protocol picks the HTTP handler. With [`acme`] on, a connection whose
//! ClientHello offers ALPN `acme-tls/1` is a certificate validation by the CA and is answered
//! apart from all of that.
//!
//! HTTP/3 ([`serve_h3`]) runs on UDP: the ClientHello is read from the client's QUIC Initial
//! packets before quinn sees them, then quinn and `h3` serve the requests.

pub mod acme;
mod capture;
mod client_match;
mod error_chain;
mod failures;
mod h3_handler;
mod h3_tap;
mod http1;
mod http2_handler;
mod limit;
mod printable;
#[cfg(test)]
mod properties;
mod quic_details;
mod report;
mod request_log;
mod routes;
mod sniff;
mod text;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fingerprint::Transport;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

pub use crate::failures::FailureLog;
pub use crate::h3_handler::serve_h3;
pub use crate::limit::ConnectionLimit;
pub use crate::request_log::{LogWriter, RequestLog};

use crate::acme::AcmeChallenges;
use crate::capture::{Rewind, read_client_hello};
use crate::report::TlsDetails;

/// How long one connection may take, handshake and request included (15 s, as on tls.peet.ws).
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the accept loop waits after a failed `accept` before trying again.
const ACCEPT_RETRY_PAUSE: Duration = Duration::from_millis(100);

/// Settings that shape responses, and where requests are logged.
#[derive(Debug, Clone)]
pub struct Config {
    /// A request with a header line starting with this text gets CORS headers;
    /// empty turns that off.
    pub cors_key: String,
    /// Gets one JSON line per routed request and per failed TLS handshake; `None` logs nothing.
    pub log: Option<RequestLog>,
    /// UDP port of the HTTP/3 listener, advertised in `Alt-Svc` on HTTP/1 and HTTP/2
    /// responses; `None` sends no `Alt-Svc`.
    pub h3_port: Option<u16>,
    /// How many connections may be open at once, TCP and QUIC together. Give [`serve`] and
    /// [`serve_h3`] the same `Config` (or clones of it) so they share the limit.
    pub connections: ConnectionLimit,
    /// Counts failed connections, TCP and QUIC together, and prints a summary on stderr.
    /// Give [`serve`] and [`serve_h3`] the same `Config` (or clones of it) to get one summary.
    pub failures: FailureLog,
    /// Certificates for the CA's validation connections (ALPN `acme-tls/1`) on TCP; `None`
    /// treats such a connection like any other. A validation connection is answered with
    /// these, takes a connection slot like any other, and is neither logged nor counted as a
    /// failure.
    pub challenges: Option<AcmeChallenges>,
}

impl Config {
    /// The `Alt-Svc` value pointing browsers at the HTTP/3 listener, if there is one.
    fn alt_svc(&self) -> Option<String> {
        self.h3_port.map(|port| format!("h3=\":{port}\"; ma=86400"))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cors_key: "X-CORS".into(),
            log: None,
            h3_port: None,
            connections: ConnectionLimit::default(),
            failures: FailureLog::default(),
            challenges: None,
        }
    }
}

/// Builds the rustls server configuration, advertising only `http/1.1`.
///
/// # Errors
///
/// Fails when the key does not match the certificate or is of an unsupported type.
pub fn tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, rustls::Error> {
    let config = server_config_builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(with_http_alpn(config))
}

/// Like [`tls_config`], but the certificate comes from `resolver` for every handshake, so a
/// certificate that changes while the server runs (see [`acme::CurrentCert`]) is picked up
/// without a restart. [`serve_h3`] takes this configuration too and uses the same resolver.
#[must_use]
pub fn tls_config_with_resolver(resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig {
    let config = server_config_builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    with_http_alpn(config)
}

/// A rustls server configuration builder on the aws-lc-rs provider, with the TLS versions
/// rustls enables by default (1.2 and 1.3).
///
/// `ServerConfig::builder()` takes the process's default provider, and when none is
/// installed it works only while exactly one of rustls's provider features is compiled in:
/// with a second one, which any dependency can turn on, it panics at first use. Naming the
/// provider keeps this crate's configurations out of that.
pub(crate) fn server_config_builder() -> rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>
{
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the aws-lc-rs provider has cipher suites for TLS 1.2 and 1.3")
}

fn with_http_alpn(mut config: ServerConfig) -> ServerConfig {
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// A fresh self-signed certificate for `localhost` and `127.0.0.1`.
///
/// # Errors
///
/// Fails only if key generation or signing fails.
pub fn self_signed_cert() -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let names = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
    let certified = rcgen::generate_simple_self_signed(names).map_err(io::Error::other)?;
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    Ok((vec![certified.cert.der().clone()], key.into()))
}

/// Accepts connections forever, handling each on its own task.
///
/// A connection that arrives while [`Config::connections`] has no free slot is closed at once.
///
/// A failed `accept` (out of file descriptors, a connection reset before it was accepted) is
/// reported on stderr and retried after a short pause, so it never stops the server.
///
/// # Errors
///
/// Never returns an error today; the `Result` leaves room for a listener that can fail for good.
pub async fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    config: Arc<Config>,
) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(tls);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("accept failed: {error}");
                tokio::time::sleep(ACCEPT_RETRY_PAUSE).await;
                continue;
            }
        };
        let Some(slot) = config.connections.try_admit() else {
            // Dropping the stream closes it; the refusal is counted by the limit.
            continue;
        };
        let acceptor = acceptor.clone();
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            let _slot = slot;
            let deadline = Instant::now() + CONNECTION_TIMEOUT;
            if let Err(error) = handle(stream, peer, &acceptor, &config, deadline).await {
                config.failures.record_io(peer, &error);
            }
        });
    }
}

/// Serves one TCP connection; every step must be done by `deadline`.
async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    acceptor: &TlsAcceptor,
    config: &Config,
    deadline: Instant,
) -> io::Result<()> {
    let (buffered, hello) = by(deadline, read_client_hello(&mut stream)).await?;
    if let Some(challenges) = &config.challenges
        && AcmeChallenges::is_challenge(&hello)
    {
        // The CA validating a name. Whatever happens, this is not a visit: nothing is logged
        // and no failure is counted, so a scanner sending acme-tls/1 shows up nowhere.
        let _ = by(deadline, challenges.respond(Rewind::new(buffered, stream))).await;
        return Ok(());
    }
    let accepted = by(deadline, acceptor.accept(Rewind::new(buffered, stream))).await;
    let tls = match accepted {
        Ok(tls) => tls,
        Err(error) => {
            if let Some(log) = &config.log {
                // Nothing was negotiated, hence version 0.
                let details = TlsDetails::new(&hello, 0, Transport::Tcp);
                log.record_failed_handshake(peer, details, &error);
            }
            return Err(error);
        }
    };
    let (_, connection) = tls.get_ref();
    let negotiated = connection.protocol_version().map_or(0, u16::from);
    let alpn = connection.alpn_protocol().map(<[u8]>::to_vec);
    let details = TlsDetails::new(&hello, negotiated, Transport::Tcp);

    match alpn.as_deref() {
        Some(b"h2") => by(deadline, http2_handler::serve(tls, peer, details, config)).await,
        _ => by(deadline, http1::serve(tls, peer, details, config)).await,
    }
}

/// Runs `step` until `deadline`; a step still running then fails with
/// [`io::ErrorKind::TimedOut`].
async fn by<T>(deadline: Instant, step: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout_at(deadline, step)
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection timed out",
            ))
        })
}
