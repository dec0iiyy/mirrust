//! The ACME client: orders a certificate, answers the validation, installs the result, and
//! does it again before the certificate runs out.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, bail};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, Order, OrderStatus, RetryPolicy,
};
use rustls::sign::CertifiedKey;

use crate::acme::cache::{CertCache, CertificateAuthority, Failures, StoredCert};
use crate::acme::cert::{CurrentCert, Validity, certified_key, validity_of};
use crate::acme::challenge::{AcmeChallenges, challenge_certificate};

/// Where the Subscriber Agreement that `--domain` accepts can be read.
const SUBSCRIBER_AGREEMENT_URL: &str = "https://letsencrypt.org/repository/";

/// How long one attempt, from the account to the certificate, may take before it counts as
/// failed. The CA validates within seconds; this only stops a stuck connection from ending
/// renewals for good.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// The wait after the first failed attempt. Let's Encrypt allows five failed validations per
/// name and hour; with this start and doubling, five attempts take 75 minutes.
const FIRST_RETRY: Duration = Duration::from_secs(5 * 60);

/// The longest wait between attempts.
const LONGEST_RETRY: Duration = Duration::from_secs(6 * 3600);

/// The longest single sleep. A long wait is cut into pieces and the wall clock is read after
/// each, because timers do not run while the machine is suspended.
const SLEEP_STEP: Duration = Duration::from_secs(12 * 3600);

/// What to certify and whom to ask.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The host names, validated (see [`domain`](crate::acme::domain)).
    pub names: Vec<String>,
    /// A contact address for the CA, used when the account is created.
    pub email: Option<String>,
    /// The CA.
    pub authority: CertificateAuthority,
}

/// Loads the certificate from `cache` if there is a valid one, and returns the task that keeps
/// the certificate current: it orders the first certificate when there is none, and renews
/// before expiry. The task never ends; run it with [`tokio::spawn`].
///
/// This prints the one-time notice about the Subscriber Agreement and the line that tells the
/// operator a certificate is on its way, before it returns.
pub fn start(
    settings: Settings,
    cache: CertCache,
    certs: Arc<CurrentCert>,
    challenges: AcmeChallenges,
) -> impl Future<Output = ()> + Send + 'static {
    let client = Client {
        settings,
        cache,
        certs,
        challenges,
    };
    eprintln!(
        "acme: --domain means you accept the Let's Encrypt Subscriber Agreement, \
         {SUBSCRIBER_AGREEMENT_URL}"
    );
    let names = client.names_text();
    let authority = client.settings.authority.label();
    let (renew_at, announced) = if let Some(validity) = client.install_cached() {
        let now = SystemTime::now();
        eprintln!(
            "acme: using the certificate for {names} from {}, valid for {} more, renewal in {}",
            client.cache.dir().display(),
            describe(validity.not_after.duration_since(now).unwrap_or_default()),
            describe(validity.renew_at().duration_since(now).unwrap_or_default()),
        );
        (validity.renew_at(), false)
    } else {
        eprintln!(
            "acme: obtaining a certificate for {names} from {authority} ...; TLS handshakes \
             fail until it arrives (the name must resolve to this server and TCP 443 must be \
             reachable)"
        );
        (SystemTime::now(), true)
    };
    let (renew_at, retry) = client.resume_after_failures(renew_at);
    client.run(renew_at, announced, retry)
}

struct Client {
    settings: Settings,
    cache: CertCache,
    certs: Arc<CurrentCert>,
    challenges: AcmeChallenges,
}

impl Client {
    fn names_text(&self) -> String {
        self.settings.names.join(", ")
    }

    /// Takes the failed attempts of earlier runs into account: the next attempt is not before
    /// the wait that followed the last one, so restarting does not retry at once. Returns the
    /// time of the next attempt and the backoff to continue with.
    fn resume_after_failures(&self, renew_at: SystemTime) -> (SystemTime, Backoff) {
        let mut retry = Backoff::new(FIRST_RETRY, LONGEST_RETRY);
        let failures = match self.cache.failures(&self.settings.names) {
            Ok(failures) => failures,
            Err(error) => {
                eprintln!("acme: cannot read the record of failed attempts: {error}");
                None
            }
        };
        let Some(failures) = failures else {
            return (renew_at, retry);
        };
        let now = SystemTime::now();
        let renew_at = retry.resume(failures, renew_at, now);
        if let Ok(wait) = renew_at.duration_since(now) {
            eprintln!(
                "acme: the last {} attempts failed; the next one is in {}",
                failures.count,
                describe(wait)
            );
        }
        (renew_at, retry)
    }

    /// Installs the cached certificate if it is for these names and still valid.
    fn install_cached(&self) -> Option<Validity> {
        let stored = match self.cache.certificate(&self.settings.names) {
            Ok(stored) => stored?,
            Err(error) => {
                eprintln!("acme: cannot read the cached certificate: {error}");
                return None;
            }
        };
        match parse(&stored) {
            Ok((key, validity)) if validity.contains(SystemTime::now()) => {
                self.certs.set(Arc::new(key));
                Some(validity)
            }
            Ok(_) => None,
            Err(error) => {
                eprintln!("acme: ignoring the cached certificate: {error:#}");
                None
            }
        }
    }

    /// Makes `stored` the certificate new handshakes get.
    fn install(&self, stored: &StoredCert) -> anyhow::Result<Validity> {
        let (key, validity) = parse(stored)?;
        self.certs.set(Arc::new(key));
        Ok(validity)
    }

    /// Orders at `renew_at`, then at each renewal time, backing off after a failure.
    async fn run(self, mut renew_at: SystemTime, mut announced: bool, mut retry: Backoff) {
        loop {
            sleep_until(renew_at).await;
            let renewing = self.certs.is_set();
            if !announced {
                eprintln!(
                    "acme: ordering a certificate for {} from {}",
                    self.names_text(),
                    self.settings.authority.label()
                );
            }
            announced = false;
            match self.attempt().await {
                Ok(validity) => {
                    let verb = if renewing { "renewed" } else { "issued" };
                    let now = SystemTime::now();
                    eprintln!(
                        "acme: {verb} the certificate for {}, valid for {}, renewal in {}",
                        self.names_text(),
                        describe(validity.not_after.duration_since(now).unwrap_or_default()),
                        describe(validity.renew_at().duration_since(now).unwrap_or_default()),
                    );
                    retry.reset();
                    if let Err(error) = self.cache.clear_failures() {
                        eprintln!("acme: cannot remove the record of failed attempts: {error}");
                    }
                    renew_at = validity.renew_at();
                }
                Err(error) => {
                    let wait = retry.next_wait();
                    eprintln!(
                        "acme: failed: {error:#}; next attempt in {}",
                        describe(wait)
                    );
                    let now = SystemTime::now();
                    renew_at = now + wait;
                    let failures = Failures {
                        count: retry.failures(),
                        at: now,
                    };
                    if let Err(error) = self.cache.save_failures(&self.settings.names, failures) {
                        eprintln!(
                            "acme: cannot record the failure in {} (a restart tries again at \
                             once): {error}",
                            self.cache.dir().display()
                        );
                    }
                }
            }
        }
    }

    /// One order, start to finish, within [`ATTEMPT_TIMEOUT`]: obtains, saves and installs.
    async fn attempt(&self) -> anyhow::Result<Validity> {
        let stored = tokio::time::timeout(ATTEMPT_TIMEOUT, self.obtain())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "no certificate after {} minutes",
                    ATTEMPT_TIMEOUT.as_secs() / 60
                )
            })??;
        let validity = self.install(&stored)?;
        // The certificate is in use whether or not it could be saved.
        if let Err(error) = self.cache.save_certificate(&self.settings.names, &stored) {
            eprintln!(
                "acme: cannot save the certificate in {} (a restart will order it again): {error}",
                self.cache.dir().display()
            );
        }
        Ok(validity)
    }

    /// The account: restored from the cache, or created and saved.
    async fn account(&self) -> anyhow::Result<Account> {
        let http = || Account::builder().context("setting up the HTTPS client");
        let saved = self.cache.account().context("reading the saved account")?;
        if let Some(json) = saved {
            match serde_json::from_str::<AccountCredentials>(&json) {
                Ok(credentials) => {
                    return http()?
                        .from_credentials(credentials)
                        .await
                        .context("restoring the ACME account");
                }
                Err(error) => eprintln!("acme: ignoring the unreadable saved account: {error}"),
            }
        }
        let contact: Vec<String> = self
            .settings
            .email
            .iter()
            .map(|email| format!("mailto:{email}"))
            .collect();
        let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
        let (account, credentials) = http()?
            .create(
                &NewAccount {
                    contact: &contact,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.settings.authority.directory_url().to_owned(),
                None,
            )
            .await
            .context("creating the ACME account")?;
        let json = serde_json::to_string(&credentials).context("saving the account")?;
        if let Err(error) = self.cache.save_account(&json) {
            eprintln!(
                "acme: cannot save the account in {} (a restart creates a new one): {error}",
                self.cache.dir().display()
            );
        }
        Ok(account)
    }

    /// Orders the certificate and answers the validation of each name.
    async fn obtain(&self) -> anyhow::Result<StoredCert> {
        let account = self.account().await?;
        let identifiers: Vec<Identifier> = self
            .settings
            .names
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .context("creating the order")?;

        let mut armed = Armed::new(&self.challenges);
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization.context("fetching an authorization")?;
            match authorization.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                status => bail!("an authorization is {status:?}"),
            }
            let mut challenge = authorization
                .challenge(ChallengeType::TlsAlpn01)
                .context("the CA offers no tls-alpn-01 challenge")?;
            let name = challenge.identifier().to_string();
            let digest = challenge.key_authorization().digest();
            let certificate = challenge_certificate(&name, digest.as_ref())?;
            armed.insert(&name, Arc::new(certificate));
            challenge
                .set_ready()
                .await
                .context("telling the CA the challenge is ready")?;
        }

        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .context("waiting for the validation")?;
        if status != OrderStatus::Ready {
            bail!("validation failed: {}", rejection(&mut order).await);
        }
        let key_pem = order.finalize().await.context("finalizing the order")?;
        let chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .context("waiting for the certificate")?;
        Ok(StoredCert { chain_pem, key_pem })
    }
}

/// The certificate in `stored`, ready to sign with, and its validity dates.
fn parse(stored: &StoredCert) -> anyhow::Result<(CertifiedKey, Validity)> {
    let key = certified_key(&stored.chain_pem, &stored.key_pem)?;
    let validity = key
        .cert
        .first()
        .and_then(|leaf| validity_of(leaf.as_ref()))
        .context("reading the certificate's validity dates")?;
    Ok((key, validity))
}

/// The CA's own words about why an order is invalid: the error of each failed challenge.
async fn rejection(order: &mut Order) -> String {
    let mut problems: Vec<String> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(Ok(mut authorization)) = authorizations.next().await {
        let name = authorization.identifier().to_string();
        match authorization.refresh().await {
            Ok(state) => problems.extend(
                state
                    .challenges
                    .iter()
                    .filter_map(|challenge| challenge.error.as_ref())
                    .map(|problem| format!("{name}: {problem}")),
            ),
            Err(error) => problems.push(format!("{name}: {error}")),
        }
    }
    if problems.is_empty() {
        "the CA gave no reason".to_owned()
    } else {
        problems.join("; ")
    }
}

/// The challenge certificates of one attempt, removed when the attempt ends however it ends.
struct Armed<'a> {
    challenges: &'a AcmeChallenges,
    names: Vec<String>,
}

impl<'a> Armed<'a> {
    fn new(challenges: &'a AcmeChallenges) -> Self {
        Self {
            challenges,
            names: Vec::new(),
        }
    }

    fn insert(&mut self, name: &str, certificate: Arc<CertifiedKey>) {
        self.challenges.insert(name, certificate);
        self.names.push(name.to_owned());
    }
}

impl Drop for Armed<'_> {
    fn drop(&mut self) {
        for name in &self.names {
            self.challenges.remove(name);
        }
    }
}

/// Waits between attempts: `first`, then twice as long each time, up to `longest`.
#[derive(Debug)]
struct Backoff {
    first: Duration,
    longest: Duration,
    failures: u32,
}

impl Backoff {
    fn new(first: Duration, longest: Duration) -> Self {
        Self {
            first,
            longest,
            failures: 0,
        }
    }

    /// The wait that follows the `failures`-th failure in a row.
    fn wait_after(&self, failures: u32) -> Duration {
        let doublings = failures.saturating_sub(1).min(32);
        self.first
            .saturating_mul(2u32.saturating_pow(doublings))
            .min(self.longest)
    }

    /// Counts one more failure and returns the wait that follows it.
    fn next_wait(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        self.wait_after(self.failures)
    }

    /// How many failures in a row have been counted.
    fn failures(&self) -> u32 {
        self.failures
    }

    fn reset(&mut self) {
        self.failures = 0;
    }

    /// Continues from `earlier` failures: counts them, and returns `renew_at` or, if that is
    /// later, the time their wait ends. A failure dated after `now` (the clock was set back)
    /// counts as having happened now.
    fn resume(&mut self, earlier: Failures, renew_at: SystemTime, now: SystemTime) -> SystemTime {
        self.failures = earlier.count;
        renew_at.max(earlier.at.min(now) + self.wait_after(earlier.count))
    }
}

async fn sleep_until(when: SystemTime) {
    while let Ok(remaining) = when.duration_since(SystemTime::now()) {
        if remaining.is_zero() {
            break;
        }
        tokio::time::sleep(remaining.min(SLEEP_STEP)).await;
    }
}

/// A span for messages: "3 days", "5 hours", "12 minutes".
fn describe(span: Duration) -> String {
    let minutes = span.as_secs() / 60;
    match minutes {
        0..=119 => format!("{minutes} minutes"),
        120..=2879 => format!("{} hours", minutes / 60),
        _ => format!("{} days", minutes / 1440),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_doubles_up_to_the_longest_and_starts_over_after_a_success() {
        let mut retry = Backoff::new(Duration::from_secs(60), Duration::from_secs(300));
        let waits: Vec<u64> = (0..5).map(|_| retry.next_wait().as_secs()).collect();
        assert_eq!(waits, [60, 120, 240, 300, 300]);
        retry.reset();
        assert_eq!(retry.next_wait().as_secs(), 60);
    }

    #[test]
    fn the_real_backoff_never_waits_less_than_five_minutes() {
        let mut retry = Backoff::new(FIRST_RETRY, LONGEST_RETRY);
        for _ in 0..20 {
            let wait = retry.next_wait();
            assert!(wait >= FIRST_RETRY && wait <= LONGEST_RETRY, "{wait:?}");
        }
    }

    #[test]
    fn a_restart_waits_out_the_backoff_of_the_failures_before_it() {
        let mut retry = Backoff::new(Duration::from_secs(60), Duration::from_secs(300));
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let earlier = Failures { count: 3, at };
        // The third failure was followed by a wait of 240 s.
        let now = at + Duration::from_secs(10);
        assert_eq!(
            retry.resume(earlier, now, now),
            at + Duration::from_secs(240)
        );
        // It goes on from the third failure: the next wait is the fourth, 300 s.
        assert_eq!(retry.next_wait().as_secs(), 300);
        assert_eq!(retry.failures(), 4);
        // A certificate that is due later is not made due sooner.
        let later = at + Duration::from_secs(5000);
        assert_eq!(retry.resume(earlier, later, now), later);
        // A failure dated in the future (clock set back) counts from now.
        let future = Failures {
            count: 1,
            at: now + Duration::from_secs(9999),
        };
        assert_eq!(
            retry.resume(future, now, now),
            now + Duration::from_secs(60)
        );
    }

    #[test]
    fn spans_are_described_in_a_readable_unit() {
        let text = |secs| describe(Duration::from_secs(secs));
        assert_eq!(text(0), "0 minutes");
        assert_eq!(text(300), "5 minutes");
        assert_eq!(text(2 * 3600 - 1), "119 minutes");
        assert_eq!(text(5 * 3600), "5 hours");
        assert_eq!(text(47 * 3600), "47 hours");
        assert_eq!(text(60 * 86_400), "60 days");
    }

    #[tokio::test]
    async fn armed_challenges_are_removed_when_the_attempt_ends() {
        let challenges = AcmeChallenges::new();
        let certificate = Arc::new(challenge_certificate("a.example.com", &[0; 32]).expect("cert"));
        {
            let mut armed = Armed::new(&challenges);
            armed.insert("a.example.com", certificate);
            assert_eq!(armed.names, ["a.example.com"]);
        }
        // The only observable effect is through a handshake, covered in `challenge`; here
        // the guard must at least run without a panic and leave nothing registered.
        assert!(challenges.is_empty());
    }

    /// A client whose cache holds a certificate for `a.example.com` valid in `years`.
    fn client_with_cached(name: &str, years: (i32, i32)) -> (Client, std::path::PathBuf) {
        use rcgen::{CertificateParams, KeyPair, date_time_ymd};

        let base =
            std::env::temp_dir().join(format!("mirrust-acme-order-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let authority = CertificateAuthority::LetsEncryptStaging;
        let cache = CertCache::open(&base, authority).expect("open the cache");
        let names = vec!["a.example.com".to_owned()];
        let mut params = CertificateParams::new(names.clone()).expect("params");
        params.not_before = date_time_ymd(years.0, 1, 1);
        params.not_after = date_time_ymd(years.1, 1, 1);
        let key = KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("certificate");
        let stored = StoredCert {
            chain_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        };
        cache.save_certificate(&names, &stored).expect("save");
        let client = Client {
            settings: Settings {
                names,
                email: None,
                authority,
            },
            cache,
            certs: Arc::new(CurrentCert::new()),
            challenges: AcmeChallenges::new(),
        };
        (client, base)
    }

    #[test]
    fn a_valid_cached_certificate_is_installed_and_an_expired_one_is_not() {
        let (valid, dir) = client_with_cached("valid", (2020, 2090));
        let validity = valid.install_cached().expect("valid certificate is used");
        assert!(validity.contains(SystemTime::now()));
        assert!(valid.certs.is_set());
        let _ = std::fs::remove_dir_all(dir);

        let (expired, dir) = client_with_cached("expired", (2019, 2020));
        assert!(expired.install_cached().is_none());
        assert!(
            !expired.certs.is_set(),
            "an expired certificate must not be served"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
