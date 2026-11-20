//! TLS-ALPN-01 (RFC 8737): the CA proves control of a name by connecting to port 443 with ALPN
//! `acme-tls/1` and checking the certificate it gets back.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::{Arc, RwLock};

use anyhow::Context as _;
use fingerprint::ClientHello as ParsedHello;
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::ServerConfig;
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio_rustls::TlsAcceptor;

/// The ALPN protocol name of a validation connection.
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// The challenge certificates the CA may ask for, by name, and the TLS acceptor that answers
/// with them. Clones share the same certificates.
#[derive(Clone)]
pub struct AcmeChallenges {
    pending: Arc<Pending>,
    acceptor: TlsAcceptor,
}

/// Challenge certificates by lowercase host name; the certificate resolver of the acceptor.
#[derive(Debug, Default)]
struct Pending(RwLock<HashMap<String, Arc<CertifiedKey>>>);

impl ResolvesServerCert for Pending {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?.to_ascii_lowercase();
        self.0.read().expect("lock poisoned").get(&name).cloned()
    }
}

impl AcmeChallenges {
    /// An empty set: every validation connection fails its handshake until a certificate is
    /// [inserted](Self::insert).
    #[must_use]
    pub fn new() -> Self {
        let pending = Arc::new(Pending::default());
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(&pending) as Arc<dyn ResolvesServerCert>);
        config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
        Self {
            pending,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }
    }

    /// Whether a ClientHello offers ALPN `acme-tls/1`: the connection is a validation, not a
    /// visit. `message` is the handshake message from its type byte on, without record
    /// headers.
    #[must_use]
    pub fn is_challenge(message: &[u8]) -> bool {
        ParsedHello::parse(message)
            .alpn
            .iter()
            .any(|protocol| protocol == ACME_TLS_ALPN)
    }

    /// Answers validation connections for `name` with `certificate` from now on.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned, which only a panic while holding it can cause.
    pub fn insert(&self, name: &str, certificate: Arc<CertifiedKey>) {
        let mut pending = self.pending.0.write().expect("lock poisoned");
        pending.insert(name.to_ascii_lowercase(), certificate);
    }

    /// Whether no certificate is registered.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.pending.0.read().expect("lock poisoned").is_empty()
    }

    /// Stops answering for `name`.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned, which only a panic while holding it can cause.
    pub fn remove(&self, name: &str) {
        let mut pending = self.pending.0.write().expect("lock poisoned");
        pending.remove(&name.to_ascii_lowercase());
    }

    /// Runs the TLS handshake of a validation connection over `stream` and closes it.
    ///
    /// # Errors
    ///
    /// Fails when the handshake fails, for instance for a name nobody asked a challenge for.
    pub(crate) async fn respond<S>(&self, stream: S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut tls = self.acceptor.accept(stream).await?;
        tls.shutdown().await
    }
}

impl Default for AcmeChallenges {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AcmeChallenges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeChallenges").finish_non_exhaustive()
    }
}

/// The certificate that proves control of `name`: self-signed, one subject alternative name,
/// and the critical `id-pe-acmeIdentifier` extension holding `digest`, the SHA-256 of the key
/// authorization (RFC 8737 section 3).
///
/// # Errors
///
/// Fails if key generation or signing fails.
pub fn challenge_certificate(name: &str, digest: &[u8]) -> anyhow::Result<CertifiedKey> {
    let mut params = CertificateParams::new(vec![name.to_owned()])
        .context("building the challenge certificate")?;
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(digest));
    let key = KeyPair::generate().context("generating the challenge key")?;
    let certificate = params
        .self_signed(&key)
        .context("signing the challenge certificate")?;
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let signing_key = any_supported_type(&key_der).context("using the challenge key")?;
    Ok(CertifiedKey::new(
        vec![certificate.der().clone()],
        signing_key,
    ))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::WebPkiSupportedAlgorithms;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::failures::FailureLog;
    use crate::request_log::RequestLog;
    use crate::{Config, self_signed_cert, serve, tls_config};

    const DIGEST: [u8; 32] = [0xab; 32];
    /// id-pe-acmeIdentifier, 1.3.6.1.5.5.7.1.31, as DER content bytes.
    const ACME_IDENTIFIER_OID: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];

    /// A client hello message (type byte on) offering `alpn`.
    fn hello(alpn: &[&[u8]]) -> Vec<u8> {
        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnything))
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|&protocol| protocol.to_vec()).collect();
        let name = ServerName::try_from("mirror.test").expect("name");
        let mut connection = ClientConnection::new(Arc::new(config), name).expect("connection");
        let mut flight = Vec::new();
        connection.write_tls(&mut flight).expect("first flight");
        flight[5..].to_vec()
    }

    #[test]
    fn the_alpn_list_decides_between_challenge_and_visit() {
        assert!(AcmeChallenges::is_challenge(&hello(&[ACME_TLS_ALPN])));
        assert!(AcmeChallenges::is_challenge(&hello(&[
            b"h2",
            ACME_TLS_ALPN
        ])));
        assert!(!AcmeChallenges::is_challenge(&hello(&[b"h2", b"http/1.1"])));
        assert!(!AcmeChallenges::is_challenge(&hello(&[b"acme-tls/2"])));
        assert!(!AcmeChallenges::is_challenge(&hello(&[])));
        assert!(!AcmeChallenges::is_challenge(b"not a hello"));
    }

    #[test]
    fn the_challenge_certificate_carries_the_critical_identifier_extension() {
        let certified = challenge_certificate("mirror.test", &DIGEST).expect("certificate");
        let der: &[u8] = certified.cert[0].as_ref();
        let oid = der
            .windows(ACME_IDENTIFIER_OID.len())
            .position(|window| window == ACME_IDENTIFIER_OID)
            .expect("the id-pe-acmeIdentifier OID is in the certificate");
        // After the OID: BOOLEAN TRUE (critical), then OCTET STRING { OCTET STRING digest }.
        let after = &der[oid + ACME_IDENTIFIER_OID.len()..];
        assert_eq!(
            &after[..5],
            [0x01, 0x01, 0xff, 0x04, 0x22],
            "critical, 34 bytes"
        );
        assert_eq!(&after[5..7], [0x04, 0x20], "an OCTET STRING of 32 bytes");
        assert_eq!(&after[7..39], DIGEST);
        let subject = b"mirror.test";
        assert!(der.windows(subject.len()).any(|window| window == subject));
    }

    /// A verifier that accepts any server certificate and signature. The challenge
    /// certificate is self-signed and has a critical extension webpki does not know, so
    /// neither a root store nor webpki's signature check accepts it; the test looks at the
    /// certificate itself.
    #[derive(Debug)]
    struct AcceptAnything;

    impl ServerCertVerifier for AcceptAnything {
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
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            algorithms().supported_schemes()
        }
    }

    fn algorithms() -> WebPkiSupportedAlgorithms {
        rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms
    }

    /// Connects with ALPN `alpn` and SNI `name`, accepting any certificate; returns the
    /// negotiated ALPN protocol and the certificate seen.
    async fn connect(
        addr: SocketAddr,
        name: &str,
        alpn: &[u8],
    ) -> io::Result<(Option<Vec<u8>>, CertificateDer<'static>)> {
        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnything))
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let name = ServerName::try_from(name.to_owned()).expect("name");
        let socket = TcpStream::connect(addr).await?;
        let tls = TlsConnector::from(Arc::new(config))
            .connect(name, socket)
            .await?;
        let (_, connection) = tls.get_ref();
        let seen = connection.peer_certificates().expect("certificate")[0].clone();
        Ok((connection.alpn_protocol().map(<[u8]>::to_vec), seen))
    }

    #[tokio::test]
    async fn a_challenge_connection_is_answered_and_leaves_no_log_line_and_no_failure() {
        let dir =
            std::env::temp_dir().join(format!("mirrust-acme-challenge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let log_path = dir.join("requests.jsonl");
        let _ = std::fs::remove_file(&log_path);
        let (log, writer) = RequestLog::open(&log_path).await.expect("open the log");

        let summaries = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&summaries);
        let failures = FailureLog::with_sink(Duration::from_millis(50), move |line| {
            sink.lock().expect("lock poisoned").push(line.to_owned());
        });

        let challenges = AcmeChallenges::new();
        let certified = Arc::new(challenge_certificate("mirror.test", &DIGEST).expect("cert"));
        challenges.insert("mirror.test", Arc::clone(&certified));
        let (certs, key) = self_signed_cert().expect("self-signed");
        let tls = Arc::new(tls_config(certs, key).expect("tls config"));
        let config = Config {
            log: Some(log),
            failures,
            challenges: Some(challenges.clone()),
            ..Config::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(serve(listener, tls, Arc::new(config)));

        // The validation gets the challenge certificate and ALPN acme-tls/1.
        let (alpn, seen) = connect(addr, "mirror.test", ACME_TLS_ALPN)
            .await
            .expect("challenge");
        assert_eq!(alpn.as_deref(), Some(ACME_TLS_ALPN));
        assert_eq!(seen, certified.cert[0]);
        // A name nobody asked for fails its handshake, and that is not counted either.
        connect(addr, "other.test", ACME_TLS_ALPN)
            .await
            .expect_err("no certificate for the name");
        // Once the challenge is over, the name gets nothing more.
        challenges.remove("mirror.test");
        connect(addr, "mirror.test", ACME_TLS_ALPN)
            .await
            .expect_err("removed");

        // Control: an ordinary client that rejects the certificate is a failed handshake, and
        // it is logged and counted, so the silence above means something.
        let roots = rustls::RootCertStore::empty();
        let strict = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from("localhost").expect("name");
        let socket = TcpStream::connect(addr).await.expect("connect");
        TlsConnector::from(Arc::new(strict))
            .connect(name, socket)
            .await
            .expect_err("untrusted certificate");

        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(writer.finish().await, 0);
        let log_lines = std::fs::read_to_string(&log_path).expect("read the log");
        assert_eq!(
            log_lines.lines().count(),
            1,
            "only the control failure: {log_lines}"
        );
        assert!(log_lines.contains("handshake"), "{log_lines}");
        let summaries = summaries.lock().expect("lock poisoned");
        assert_eq!(summaries.len(), 1, "{summaries:?}");
        assert!(
            summaries[0].starts_with("1 connections failed"),
            "{summaries:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
