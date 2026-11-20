//! `mirrust` binary: serves the fingerprint API over HTTPS.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use server::acme::domain::{self, AUTO, MAX_DOMAINS};
use server::acme::{
    AcmeChallenges, CertCache, CertificateAuthority, CurrentCert, Settings as AcmeSettings,
};
use server::{
    Config, ConnectionLimit, RequestLog, self_signed_cert, serve, serve_h3, tls_config,
    tls_config_with_resolver,
};
use tokio::net::TcpListener;

mod install;

const USAGE: &str = "usage: mirrust [--listen ADDR] [--cert PEM --key PEM | --domain NAME ...]
                  [--acme-dir DIR] [--acme-email ADDR] [--acme-staging]
                  [--cors-key KEY] [--log PATH] [--max-connections N]
       mirrust install (--domain NAME ... | --cert PEM --key PEM) [--dry-run] ...
       mirrust uninstall [--dry-run]
       mirrust --version

  -h, --help         print this text and exit
  -V, --version      print the version and exit

install sets mirrust up as a systemd service (Linux, as root) and uninstall removes it; see
mirrust install --help for their flags.

  --listen           address to listen on, TCP and UDP for HTTP/3 (default 127.0.0.1:8443,
                     0.0.0.0:443 with --domain)
  --cert/--key       PEM certificate chain and private key; without them, and without
                     --domain, a self-signed certificate for localhost is generated
  --domain           get a Let's Encrypt certificate for this host name and renew it, with
                     no other setup (TLS-ALPN-01 on TCP port 443; the name must resolve to
                     this server). Repeat for up to 4 names. 'auto' uses A-B-C-D.sslip.io
                     for this machine's public IPv4 address (sslip.io is a free third-party
                     DNS service). Using it accepts the Let's Encrypt Subscriber Agreement
                     (https://letsencrypt.org/repository/). Conflicts with --cert/--key
  --acme-dir         where the ACME account key and the certificates are kept
                     (default ./mirrust-acme, created with mode 0700)
  --acme-email       contact address for Let's Encrypt, used when the account is created
  --acme-staging     use the Let's Encrypt staging CA (certificates browsers do not trust,
                     no rate limits that matter): for trying --domain out
  --cors-key         header prefix that turns on CORS headers (default X-CORS, empty: off)
  --log              append one JSON line per request and per failed TLS handshake to
                     this file (default: no log)
  --max-connections  connections open at once, TCP and QUIC together; more are refused
                     (default 1024)";

/// The default for `--acme-dir`.
const DEFAULT_ACME_DIR: &str = "./mirrust-acme";

/// The port Let's Encrypt validates on, whatever the server listens on.
const VALIDATION_PORT: u16 = 443;

/// The default for `--listen`.
const DEFAULT_LISTEN: &str = "127.0.0.1:8443";
/// The default for `--listen` when `--domain` is given: the address Let's Encrypt can reach.
const DEFAULT_LISTEN_ACME: &str = "0.0.0.0:443";

/// What `--domain` and the `--acme-*` flags asked for, before the names are resolved.
#[derive(Debug, PartialEq, Eq)]
struct AcmeArgs {
    /// The `--domain` values as given, `auto` still unresolved.
    domains: Vec<String>,
    dir: PathBuf,
    email: Option<String>,
    staging: bool,
}

#[derive(Debug)]
struct Args {
    listen: SocketAddr,
    cert: Option<(PathBuf, PathBuf)>,
    acme: Option<AcmeArgs>,
    log: Option<PathBuf>,
    config: Config,
}

/// What the command line asks the program to do.
#[derive(Debug)]
enum Command {
    Run(Box<Args>),
    Help,
    Version,
    /// `install` or `uninstall`, with their own flags.
    Manage(install::Request),
}

/// The text `--version` prints.
fn version_line() -> String {
    format!("mirrust {}", env!("CARGO_PKG_VERSION"))
}

fn parse_args(args: impl IntoIterator<Item = String>) -> anyhow::Result<Command> {
    let mut listen: Option<SocketAddr> = None;
    let mut cert = None;
    let mut key = None;
    let mut log = None;
    let mut domains: Vec<String> = Vec::new();
    let mut acme_dir = None;
    let mut acme_email = None;
    let mut acme_staging = false;
    let mut config = Config::default();
    let mut args = args.into_iter().peekable();
    if let Some(name) = args.next_if(|arg| matches!(arg.as_str(), "install" | "uninstall")) {
        return install::parse(&name, args).map(Command::Manage);
    }
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--acme-staging" => {
                acme_staging = true;
                continue;
            }
            _ => {}
        }
        let value = args
            .next()
            .with_context(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--listen" => {
                listen = Some(
                    value
                        .parse()
                        .with_context(|| format!("bad --listen {value}"))?,
                );
            }
            "--cert" => cert = Some(PathBuf::from(value)),
            "--key" => key = Some(PathBuf::from(value)),
            "--domain" => domains.push(value),
            "--acme-dir" => acme_dir = Some(PathBuf::from(value)),
            "--acme-email" => acme_email = Some(check_email(value)?),
            "--cors-key" => config.cors_key = value,
            "--log" => log = Some(PathBuf::from(value)),
            "--max-connections" => {
                let max = value
                    .parse()
                    .ok()
                    .filter(|&max: &usize| max > 0)
                    .with_context(|| format!("bad --max-connections {value}"))?;
                config.connections = ConnectionLimit::new(max);
            }
            _ => bail!("unknown flag {flag}\n{USAGE}"),
        }
    }
    let cert = match (cert, key) {
        (Some(cert), Some(key)) => Some((cert, key)),
        (None, None) => None,
        _ => bail!("--cert and --key go together"),
    };
    let acme = if domains.is_empty() {
        if acme_dir.is_some() || acme_email.is_some() || acme_staging {
            bail!("--acme-dir, --acme-email and --acme-staging only mean something with --domain");
        }
        None
    } else {
        if cert.is_some() {
            bail!("--domain gets its own certificate and conflicts with --cert/--key; use one");
        }
        if domains.len() > MAX_DOMAINS {
            bail!(
                "at most {MAX_DOMAINS} --domain names, got {}",
                domains.len()
            );
        }
        Some(AcmeArgs {
            domains,
            dir: acme_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_ACME_DIR)),
            email: acme_email,
            staging: acme_staging,
        })
    };
    let default_listen = if acme.is_some() {
        DEFAULT_LISTEN_ACME
    } else {
        DEFAULT_LISTEN
    };
    let listen = listen.unwrap_or_else(|| default_listen.parse().expect("valid default address"));
    Ok(Command::Run(Box::new(Args {
        listen,
        cert,
        acme,
        log,
        config,
    })))
}

/// Accepts an address of the form `local@host`, with no spaces and nothing that would break
/// the `mailto:` URI the CA is given.
fn check_email(value: String) -> anyhow::Result<String> {
    let valid = value.split_once('@').is_some_and(|(local, host)| {
        !local.is_empty() && host.contains('.') && !host.contains('@')
    }) && !value
        .contains(|c: char| c.is_whitespace() || c.is_control() || "?,<>&".contains(c));
    if valid {
        Ok(value)
    } else {
        bail!("bad --acme-email {value}: expected an address like admin@example.com")
    }
}

/// Starts listening for the signals that stop the server: Ctrl-C (SIGINT) and SIGTERM, which
/// is what `systemd` and `kill` send. The returned future resolves when one arrives.
///
/// The handlers are in place when this returns, before the future is first polled, so a
/// signal sent as soon as the listening line is printed is not missed.
#[cfg(unix)]
fn shutdown_signal() -> io::Result<impl Future<Output = io::Result<()>>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        Ok(())
    })
}

/// Resolves on Ctrl-C, the only stop signal off Unix.
#[cfg(not(unix))]
fn shutdown_signal() -> io::Result<impl Future<Output = io::Result<()>>> {
    Ok(tokio::signal::ctrl_c())
}

/// The TLS configuration for a fixed certificate: the PEM files given, or a self-signed one.
fn static_tls(files: Option<&(PathBuf, PathBuf)>) -> anyhow::Result<ServerConfig> {
    let (certs, key) = match files {
        Some((cert, key)) => (
            CertificateDer::pem_file_iter(cert)
                .and_then(Iterator::collect)
                .with_context(|| format!("reading {}", cert.display()))?,
            PrivateKeyDer::from_pem_file(key)
                .with_context(|| format!("reading {}", key.display()))?,
        ),
        None => self_signed_cert().context("generating a self-signed certificate")?,
    };
    tls_config(certs, key).context("building the TLS configuration")
}

/// The ACME pieces `--domain` sets up, before anything is printed or listened on.
struct Acme {
    settings: AcmeSettings,
    cache: CertCache,
    certs: Arc<CurrentCert>,
    challenges: AcmeChallenges,
}

/// Resolves the names (`auto` included) and opens the cache directory, so that a bad name or an
/// unwritable directory stops the start instead of failing later in the background.
fn prepare_acme(args: AcmeArgs) -> anyhow::Result<Acme> {
    let names = domain::resolve(&args.domains, domain::default_route_ipv4)?;
    if args.domains == [AUTO] {
        eprintln!("acme: --domain auto: using {}", names[0]);
    }
    let authority = if args.staging {
        CertificateAuthority::LetsEncryptStaging
    } else {
        CertificateAuthority::LetsEncrypt
    };
    let cache = CertCache::open(&args.dir, authority)?;
    Ok(Acme {
        settings: AcmeSettings {
            names,
            email: args.email,
            authority,
        },
        cache,
        certs: Arc::new(CurrentCert::new()),
        challenges: AcmeChallenges::new(),
    })
}

/// The error for a failed `bind`. A busy port is the usual cause on a desktop, typically another
/// mirrust that is still running, so say that and what to do about it.
fn bind_error(protocol: &str, addr: SocketAddr, error: std::io::Error) -> anyhow::Error {
    let hint = match error.kind() {
        std::io::ErrorKind::AddrInUse => format!(
            "\nport {} is already in use, probably by another mirrust that is still running; \
             stop it, or listen elsewhere with --listen 127.0.0.1:<another port>",
            addr.port()
        ),
        std::io::ErrorKind::PermissionDenied if addr.port() < 1024 => format!(
            "\nport {} needs privileges on this system; use a port above 1023 or run as a user \
             that may bind it",
            addr.port()
        ),
        _ => String::new(),
    };
    anyhow::Error::new(error).context(format!("cannot listen on {protocol} {addr}{hint}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = match parse_args(std::env::args().skip(1))? {
        Command::Help => {
            println!("{USAGE}");
            return Ok(());
        }
        Command::Version => {
            println!("{}", version_line());
            return Ok(());
        }
        Command::Manage(request) => return install::run(request),
        Command::Run(args) => *args,
    };
    let acme = args.acme.take().map(prepare_acme).transpose()?;
    // With no certificate files and no --domain the server makes its own certificate.
    let self_signed = acme.is_none() && args.cert.is_none();
    let tls = if let Some(acme) = &acme {
        args.config.challenges = Some(acme.challenges.clone());
        tls_config_with_resolver(Arc::clone(&acme.certs) as _)
    } else {
        static_tls(args.cert.as_ref())?
    };
    let tls = Arc::new(tls);
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|error| bind_error("tcp", args.listen, error))?;
    let writer = match &args.log {
        Some(path) => {
            let (log, writer) = RequestLog::open(path)
                .await
                .with_context(|| format!("opening the request log {}", path.display()))?;
            args.config.log = Some(log);
            Some(writer)
        }
        None => None,
    };
    let addr = listener.local_addr()?;
    // HTTP/3 on the same address and port, over UDP.
    let udp = UdpSocket::bind(addr).map_err(|error| bind_error("udp", addr, error))?;
    let mut config = args.config;
    config.h3_port = Some(addr.port());
    let config = Arc::new(config);
    let shutdown = shutdown_signal().context("installing the signal handlers")?;
    let renewals = acme.map(|acme| {
        if addr.port() != VALIDATION_PORT {
            eprintln!(
                "warning: listening on port {}, but Let's Encrypt validates on TCP port {VALIDATION_PORT} \
                 only; issuance will fail unless port {VALIDATION_PORT} reaches this server",
                addr.port()
            );
        }
        tokio::spawn(server::acme::start(
            acme.settings,
            acme.cache,
            acme.certs,
            acme.challenges,
        ))
    });
    println!("listening on https://{addr} (TCP and HTTP/3 over UDP)");
    if self_signed {
        let port = addr.port();
        println!(
            "self-signed certificate: open https://localhost:{port} in a browser and accept \
             the warning, or run: curl -k https://localhost:{port}"
        );
    }

    let served = tokio::select! {
        served = async {
            tokio::try_join!(
                serve(listener, Arc::clone(&tls), Arc::clone(&config)),
                serve_h3(udp, tls, config),
            )
            .map(|_| ())
        } => served,
        // The task keeps the certificate current and never ends; if it does, the certificate
        // would silently expire, so the server stops instead.
        stopped = async {
            match renewals {
                Some(task) => {
                    let ended = task.await;
                    Err(io::Error::other(format!("the certificate task stopped: {ended:?}")))
                }
                None => std::future::pending().await,
            }
        } => stopped,
        // Dropping the other branch stops accepting; connections still in progress end when
        // the process exits.
        signal = shutdown => signal,
    };
    if let Some(writer) = writer {
        let dropped = writer.finish().await;
        if dropped > 0 {
            eprintln!("request log: {dropped} entries dropped (queue full)");
        }
    }
    served?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> anyhow::Result<Args> {
        match parse_args(args.iter().map(|&arg| arg.to_owned()))? {
            Command::Run(args) => Ok(*args),
            Command::Help => bail!("help"),
            Command::Version => bail!("version"),
            Command::Manage(_) => bail!("install or uninstall"),
        }
    }

    fn error(args: &[&str]) -> String {
        format!("{:#}", parse(args).expect_err("should be refused"))
    }

    #[test]
    fn without_domain_nothing_changes() {
        let args = parse(&[
            "--listen",
            "0.0.0.0:443",
            "--cert",
            "c.pem",
            "--key",
            "k.pem",
        ])
        .expect("valid");
        assert!(args.acme.is_none());
        assert_eq!(
            args.cert,
            Some((PathBuf::from("c.pem"), PathBuf::from("k.pem")))
        );
        assert!(parse(&[]).expect("no flags").acme.is_none());
        assert!(matches!(
            parse_args(["--help".to_owned()]).expect("help"),
            Command::Help
        ));
    }

    #[test]
    fn version_flags_ask_for_the_version() {
        for flag in ["--version", "-V"] {
            assert!(
                matches!(
                    parse_args([flag.to_owned()]).expect("version"),
                    Command::Version
                ),
                "{flag}"
            );
        }
        // Like --help, it wins over whatever follows or precedes it.
        let with_others = ["--listen", "0.0.0.0:443", "-V", "--bogus"];
        assert!(matches!(
            parse_args(with_others.map(str::to_owned)).expect("version"),
            Command::Version
        ));
    }

    #[test]
    fn the_default_listen_address_follows_domain() {
        let plain = parse(&[]).expect("valid");
        assert_eq!(plain.listen.to_string(), "127.0.0.1:8443");
        let acme = parse(&["--domain", "mirror.example.com"]).expect("valid");
        assert_eq!(acme.listen.to_string(), "0.0.0.0:443");
        let explicit =
            parse(&["--domain", "mirror.example.com", "--listen", "0.0.0.0:8444"]).expect("valid");
        assert_eq!(explicit.listen.to_string(), "0.0.0.0:8444");
    }

    #[test]
    fn domain_has_documented_defaults() {
        let acme = parse(&["--domain", "mirror.example.com"])
            .expect("valid")
            .acme
            .expect("acme");
        assert_eq!(
            acme,
            AcmeArgs {
                domains: vec!["mirror.example.com".to_owned()],
                dir: PathBuf::from("./mirrust-acme"),
                email: None,
                staging: false,
            }
        );
    }

    #[test]
    fn all_acme_flags_are_read_and_domain_repeats() {
        let acme = parse(&[
            "--domain",
            "a.example.com",
            "--acme-staging",
            "--domain",
            "b.example.com",
            "--acme-dir",
            "/var/lib/mirrust",
            "--acme-email",
            "admin@example.com",
        ])
        .expect("valid")
        .acme
        .expect("acme");
        assert_eq!(acme.domains, ["a.example.com", "b.example.com"]);
        assert_eq!(acme.dir, PathBuf::from("/var/lib/mirrust"));
        assert_eq!(acme.email.as_deref(), Some("admin@example.com"));
        assert!(acme.staging);
    }

    #[test]
    fn domain_conflicts_with_cert_and_key() {
        for args in [
            [
                "--domain",
                "a.example.com",
                "--cert",
                "c.pem",
                "--key",
                "k.pem",
            ],
            [
                "--cert",
                "c.pem",
                "--key",
                "k.pem",
                "--domain",
                "a.example.com",
            ],
        ] {
            let message = error(&args);
            assert!(message.contains("conflicts with --cert/--key"), "{message}");
        }
    }

    #[test]
    fn acme_flags_need_domain() {
        for args in [
            &["--acme-staging"][..],
            &["--acme-dir", "d"],
            &["--acme-email", "a@example.com"],
        ] {
            let message = error(args);
            assert!(
                message.contains("only mean something with --domain"),
                "{message}"
            );
        }
    }

    #[test]
    fn too_many_domains_and_bad_emails_are_refused() {
        let many = [
            "--domain", "a.com", "--domain", "b.com", "--domain", "c.com", "--domain", "d.com",
            "--domain", "e.com",
        ];
        assert!(error(&many).contains("at most 4"));
        for bad in [
            "nobody",
            "@example.com",
            "a@b",
            "a b@example.com",
            "a@example.com?x=1",
        ] {
            let message = error(&["--domain", "a.example.com", "--acme-email", bad]);
            assert!(message.contains("bad --acme-email"), "{bad}: {message}");
        }
    }

    #[test]
    fn a_flag_without_a_value_is_an_error() {
        assert!(error(&["--domain"]).contains("--domain needs a value"));
        assert!(error(&["--acme-dir"]).contains("--acme-dir needs a value"));
        assert!(error(&["--bogus", "x"]).contains("unknown flag"));
    }

    #[test]
    fn a_busy_port_is_explained() {
        let addr: SocketAddr = "127.0.0.1:8443".parse().expect("address");
        let busy = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let text = format!("{:#}", bind_error("tcp", addr, busy));
        assert!(
            text.contains("cannot listen on tcp 127.0.0.1:8443"),
            "{text}"
        );
        assert!(text.contains("already in use"), "{text}");
        assert!(text.contains("--listen"), "{text}");

        let other = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let text = format!("{:#}", bind_error("udp", addr, other));
        assert!(!text.contains("already in use"), "{text}");
    }
}
