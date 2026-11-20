//! The in-process server behind `mirrust probe`.
//!
//! It listens on loopback with a throwaway certificate and keeps what it saw in memory:
//! nothing goes to disk, and nothing is printed per request.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::report::{Report, to_go_json};
use crate::text::{self, Colour};
use crate::{Config, FailureLog, keep_syn, serve, serve_h3, tls_config};

/// How many TCP ports are tried to find one whose UDP port is free too.
const PORT_ATTEMPTS: usize = 16;
/// Probe prints no failure summaries (it counts failed handshakes itself), so this only says
/// how long a silent summary task waits.
const FAILURE_SUMMARY_INTERVAL: Duration = Duration::from_secs(30);

/// Routed requests and failed TLS handshakes, kept in memory; clones share the record.
#[derive(Debug, Clone, Default)]
pub struct Visits {
    inner: Arc<Record>,
}

#[derive(Debug, Default)]
struct Record {
    reports: Mutex<Vec<Report>>,
    failed_handshakes: AtomicU64,
}

impl Visits {
    pub(crate) fn record(&self, report: &Report) {
        self.inner
            .reports
            .lock()
            .expect("lock poisoned")
            .push(report.clone());
    }

    pub(crate) fn record_failed_handshake(&self) {
        self.inner.failed_handshakes.fetch_add(1, Ordering::Relaxed);
    }

    /// Everything recorded so far, in the order the requests were routed.
    fn seen(&self) -> Seen {
        let visits = self
            .inner
            .reports
            .lock()
            .expect("lock poisoned")
            .iter()
            .map(Visit::new)
            .collect();
        Seen {
            visits,
            failed_handshakes: self.inner.failed_handshakes.load(Ordering::Relaxed),
        }
    }
}

/// What a [`Visits`] recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// One entry per routed request.
    pub visits: Vec<Visit>,
    /// TLS handshakes over TCP that failed after the ClientHello was read, such as a client
    /// that does not trust the certificate. QUIC handshakes are not counted.
    pub failed_handshakes: u64,
}

/// One routed request, as the server reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Visit {
    /// The audit score, 0 to 100. A routed request always has a ClientHello to audit.
    pub score: u8,
    /// The plain-text report, what `curl` prints for `/`.
    pub text: String,
    /// The report as one line of JSON, the body of `/api/all` without the indentation.
    pub json: String,
}

impl Visit {
    fn new(report: &Report) -> Self {
        Self {
            score: report.audit().map_or(0, |audit| audit.score),
            text: text::render(report, Colour::Plain),
            json: to_go_json(&report.to_json()),
        }
    }
}

/// A server on `127.0.0.1` for one run of `mirrust probe`: TCP and HTTP/3 on the same random
/// port, a self-signed certificate valid for `127.0.0.1` and `localhost`, and a [`Visits`]
/// record instead of a log.
#[derive(Debug)]
pub struct ProbeServer {
    addr: SocketAddr,
    cert_pem: String,
    visits: Visits,
    task: JoinHandle<io::Result<()>>,
}

impl ProbeServer {
    /// Binds the ports and starts serving on the current tokio runtime.
    ///
    /// # Errors
    ///
    /// Fails when the certificate cannot be made or no pair of free ports is found.
    pub async fn start() -> io::Result<Self> {
        let certified = crate::self_signed()?;
        let cert_pem = certified.cert.pem();
        let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let tls =
            tls_config(vec![certified.cert.der().clone()], key.into()).map_err(io::Error::other)?;
        let tls = Arc::new(tls);

        let (listener, udp) = bind_pair().await?;
        let addr = listener.local_addr()?;
        // Before anything can connect: the kernel keeps only the SYNs that arrive after this.
        keep_syn(&listener);
        let visits = Visits::default();
        let config = Arc::new(Config {
            h3_port: Some(addr.port()),
            visits: Some(visits.clone()),
            failures: FailureLog::with_sink(FAILURE_SUMMARY_INTERVAL, |_| {}),
            ..Config::default()
        });
        let task = tokio::spawn(async move {
            tokio::try_join!(
                serve(listener, Arc::clone(&tls), Arc::clone(&config)),
                serve_h3(udp, tls, config),
            )
            .map(|_| ())
        });
        Ok(Self {
            addr,
            cert_pem,
            visits,
            task,
        })
    }

    /// The address the server listens on, TCP and UDP.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The server's certificate in PEM, which is all a client needs to trust it.
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Stops the server and returns what it saw.
    ///
    /// # Errors
    ///
    /// Fails with the error of a listener that stopped before this call, which a running
    /// server never does.
    pub async fn stop(self) -> io::Result<Seen> {
        if self.task.is_finished() {
            self.task.await.map_err(io::Error::other)??;
        } else {
            self.task.abort();
        }
        Ok(self.visits.seen())
    }
}

/// A TCP listener on a random loopback port and a UDP socket on the same port number, as in
/// the server's normal mode, so that `curl --http3` finds HTTP/3 where `Alt-Svc` says.
async fn bind_pair() -> io::Result<(TcpListener, UdpSocket)> {
    for _ in 0..PORT_ATTEMPTS {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        match UdpSocket::bind(listener.local_addr()?) {
            Ok(udp) => return Ok((listener, udp)),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no TCP port found with the same UDP port free",
    ))
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::*;

    #[tokio::test]
    async fn the_certificate_names_loopback_and_localhost() {
        let server = ProbeServer::start().await.expect("start");
        let der = CertificateDer::pem_slice_iter(server.cert_pem().as_bytes())
            .next()
            .expect("one certificate")
            .expect("valid PEM");
        let (_, cert) = X509Certificate::from_der(&der).expect("valid certificate");
        let names: Vec<String> = cert
            .extensions()
            .iter()
            .filter_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(sans) => Some(sans),
                _ => None,
            })
            .flat_map(|sans| &sans.general_names)
            .map(|name| match name {
                GeneralName::DNSName(dns) => (*dns).to_owned(),
                GeneralName::IPAddress(bytes) => format!("{bytes:?}"),
                other => format!("{other:?}"),
            })
            .collect();
        assert!(names.contains(&"localhost".to_owned()), "{names:?}");
        assert!(names.contains(&"[127, 0, 0, 1]".to_owned()), "{names:?}");
        assert!(server.addr().ip().is_loopback());
        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn nothing_seen_is_nothing_reported() {
        let server = ProbeServer::start().await.expect("start");
        let seen = server.stop().await.expect("stop");
        assert_eq!(
            seen,
            Seen {
                visits: Vec::new(),
                failed_handshakes: 0
            }
        );
    }
}
