//! The certificate the server presents, which can be replaced while it runs, and the validity
//! dates of a certificate.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// The most the CA's certificate lifetime is cut by when choosing the renewal time: renew
/// this long before the end, or at a third of the lifetime if that is sooner.
const RENEW_BEFORE_END: Duration = Duration::from_secs(30 * 24 * 3600);

/// The server's certificate for normal connections, TCP and QUIC. It is empty until the first
/// certificate arrives; a handshake before then fails, and one after it gets whatever
/// [`set`](Self::set) stored last.
#[derive(Debug, Default)]
pub struct CurrentCert {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

impl CurrentCert {
    /// An empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes `key` the certificate that new handshakes get. Handshakes under way keep theirs.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned, which only a panic while holding it can cause.
    pub fn set(&self, key: Arc<CertifiedKey>) {
        *self.current.write().expect("lock poisoned") = Some(key);
    }

    /// Whether a certificate has been set.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned, which only a panic while holding it can cause.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.current.read().expect("lock poisoned").is_some()
    }
}

impl ResolvesServerCert for CurrentCert {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().expect("lock poisoned").clone()
    }
}

/// A certificate chain and its private key, as PEM text, turned into what rustls signs with.
///
/// # Errors
///
/// Fails when the PEM holds no certificate or no key, or the key type is not supported.
pub fn certified_key(chain_pem: &str, key_pem: &str) -> anyhow::Result<CertifiedKey> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .collect::<Result<_, _>>()
        .context("reading the certificate chain")?;
    anyhow::ensure!(!chain.is_empty(), "the certificate chain is empty");
    let key =
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).context("reading the private key")?;
    let signing_key = any_supported_type(&key).context("the private key type is not supported")?;
    Ok(CertifiedKey::new(chain, signing_key))
}

/// The dates a certificate is valid between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// The start of the validity period.
    pub not_before: SystemTime,
    /// The end of the validity period.
    pub not_after: SystemTime,
}

impl Validity {
    /// When to ask for a new certificate: 30 days before the end, or a third of the lifetime
    /// before it for a certificate that lives less than 90 days.
    #[must_use]
    pub fn renew_at(&self) -> SystemTime {
        let lifetime = self
            .not_after
            .duration_since(self.not_before)
            .unwrap_or_default();
        self.not_after - RENEW_BEFORE_END.min(lifetime / 3)
    }

    /// Whether `now` is inside the validity period.
    #[must_use]
    pub fn contains(&self, now: SystemTime) -> bool {
        self.not_before <= now && now < self.not_after
    }
}

/// The validity of a DER-encoded X.509 certificate; `None` if it cannot be read.
///
/// Reads `tbsCertificate.validity` by walking the DER structure (RFC 5280 section 4.1) so that
/// no X.509 parser is needed for two dates.
#[must_use]
pub fn validity_of(cert_der: &[u8]) -> Option<Validity> {
    const SEQUENCE: u8 = 0x30;
    const CONTEXT_0: u8 = 0xa0;
    let (_, certificate, _) = tlv(cert_der, SEQUENCE)?;
    let (_, mut tbs, _) = tlv(certificate, SEQUENCE)?;
    // [0] version is optional; then serial number, signature algorithm and issuer.
    if tbs.first() == Some(&CONTEXT_0) {
        tbs = tlv(tbs, CONTEXT_0)?.2;
    }
    for _ in 0..3 {
        tbs = tlv_any(tbs)?.2;
    }
    let (_, times, _) = tlv(tbs, SEQUENCE)?;
    let (not_before, rest) = time(times)?;
    let (not_after, _) = time(rest)?;
    Some(Validity {
        not_before,
        not_after,
    })
}

/// Splits `input` at the first DER element, which must have `tag`; returns the tag, the
/// contents and what follows.
fn tlv(input: &[u8], tag: u8) -> Option<(u8, &[u8], &[u8])> {
    let element = tlv_any(input)?;
    (element.0 == tag).then_some(element)
}

fn tlv_any(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |len, &byte| len << 8 | usize::from(byte));
        (len, &rest[count..])
    };
    let contents = rest.get(..len)?;
    Some((tag, contents, &rest[len..]))
}

/// Reads a `UTCTime` or `GeneralizedTime` at the start of `input`.
fn time(input: &[u8]) -> Option<(SystemTime, &[u8])> {
    const UTC_TIME: u8 = 0x17;
    const GENERALIZED_TIME: u8 = 0x18;
    let (tag, text, rest) = tlv_any(input)?;
    let text = std::str::from_utf8(text).ok()?.strip_suffix('Z')?;
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = text.get(range)?;
        digits
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| digits.parse().ok())?
    };
    let (year, rest_start) = match tag {
        UTC_TIME => {
            let yy = number(0..2)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        GENERALIZED_TIME => (number(0..4)?, 4),
        _ => return None,
    };
    let s = rest_start;
    let (month, day) = (number(s..s + 2)?, number(s + 2..s + 4)?);
    let (hour, minute, second) = (
        number(s + 4..s + 6)?,
        number(s + 6..s + 8)?,
        number(s + 8..s + 10)?,
    );
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    let seconds = u64::try_from(seconds).ok()?;
    Some((UNIX_EPOCH + Duration::from_secs(seconds), rest))
}

/// Days from 1970-01-01 to the given proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair, date_time_ymd};
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::duplex;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;

    struct Issued {
        chain_pem: String,
        key_pem: String,
        der: CertificateDer<'static>,
    }

    fn issue(name: &str, not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> Issued {
        let mut params = CertificateParams::new(vec![name.to_owned()]).expect("params");
        params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key = KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("certificate");
        Issued {
            chain_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            der: cert.der().clone(),
        }
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn reads_both_time_encodings() {
        // 1893456000 is 2030-01-01T00:00:00Z. Years from 2050 on use GeneralizedTime.
        let cert = issue("localhost", (2030, 1, 1), (2060, 3, 5));
        let validity = validity_of(&cert.der).expect("validity");
        assert_eq!(validity.not_before, at(1_893_456_000));
        // 2060-03-05: the date command gave 2845670400 for 2060-03-05T00:00:00Z.
        assert_eq!(validity.not_after, at(2_845_670_400));
        assert!(validity_of(&cert.der[..40]).is_none());
        assert!(validity_of(b"").is_none());
    }

    #[test]
    fn renewal_comes_30_days_before_the_end_or_a_third_of_a_short_life() {
        let day = 86_400;
        let long = Validity {
            not_before: at(0),
            not_after: at(90 * day),
        };
        assert_eq!(long.renew_at(), at(60 * day));
        let short = Validity {
            not_before: at(0),
            not_after: at(45 * day),
        };
        assert_eq!(short.renew_at(), at(30 * day));
        assert!(long.contains(at(day)));
        assert!(!long.contains(at(90 * day)));
    }

    #[test]
    fn certified_key_reads_pem_and_rejects_empty_input() {
        let cert = issue("localhost", (2030, 1, 1), (2031, 1, 1));
        assert!(certified_key(&cert.chain_pem, &cert.key_pem).is_ok());
        assert!(certified_key("", &cert.key_pem).is_err());
        assert!(certified_key(&cert.chain_pem, "").is_err());
    }

    /// Does a TLS handshake against `resolver` and returns the certificate the client saw, or
    /// the error.
    async fn handshake(
        resolver: &Arc<CurrentCert>,
        roots: &RootCertStore,
    ) -> Result<CertificateDer<'static>, String> {
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(resolver) as Arc<dyn ResolvesServerCert>);
        let client = ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        let (client_end, server_end) = duplex(16 * 1024);
        let accepting = TlsAcceptor::from(Arc::new(server)).accept(server_end);
        let name = ServerName::try_from("localhost").expect("name");
        let connecting = TlsConnector::from(Arc::new(client)).connect(name, client_end);
        let (accepted, connected) = tokio::join!(accepting, connecting);
        accepted.map_err(|e| e.to_string())?;
        let connected = connected.map_err(|e| e.to_string())?;
        let (_, connection) = connected.get_ref();
        Ok(connection.peer_certificates().expect("peer certs")[0].clone())
    }

    #[tokio::test]
    async fn the_resolver_fails_until_set_and_then_follows_each_update() {
        let first = issue("localhost", (2020, 1, 1), (2040, 1, 1));
        let second = issue("localhost", (2020, 1, 1), (2041, 1, 1));
        let mut roots = RootCertStore::empty();
        roots.add(first.der.clone()).expect("root");
        roots.add(second.der.clone()).expect("root");

        let resolver = Arc::new(CurrentCert::new());
        assert!(!resolver.is_set());
        assert!(handshake(&resolver, &roots).await.is_err());

        let key = |cert: &Issued| {
            Arc::new(certified_key(&cert.chain_pem, &cert.key_pem).expect("certified key"))
        };
        resolver.set(key(&first));
        assert!(resolver.is_set());
        assert_eq!(
            handshake(&resolver, &roots).await.expect("first"),
            first.der
        );

        resolver.set(key(&second));
        assert_eq!(
            handshake(&resolver, &roots).await.expect("second"),
            second.der
        );
    }
}
