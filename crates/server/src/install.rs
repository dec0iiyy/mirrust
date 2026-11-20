//! `mirrust install` and `mirrust uninstall`: set mirrust up as a systemd service, or remove it.
//!
//! `install` copies the running executable to [`BINARY_PATH`], writes the unit
//! [`UNIT_PATH`] and starts the service. The unit is not kept in this file: it is
//! `deploy/mirrust.service`, embedded at build time, with its `ExecStart=` block replaced by
//! one built from the flags given (and `LoadCredential=` lines added for `--cert`/`--key`).
//! Everything that decides what is written is a pure function; `--dry-run` prints the steps
//! and the unit text that those functions produce and touches nothing.
//!
//! This module makes no network connections.

use std::fmt::{self, Display};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use server::acme::domain::{self, AUTO, MAX_DOMAINS};

use crate::check_email;

/// The help text of `mirrust install` and `mirrust uninstall`.
pub(crate) const USAGE: &str = "usage: mirrust install (--domain NAME ... | --cert PEM --key PEM)
                        [--acme-email ADDR] [--acme-staging] [--log PATH]
                        [--max-connections N] [--dry-run]
       mirrust uninstall [--dry-run]

Linux with systemd only, as root (sudo). install copies this executable to
/usr/local/bin/mirrust, writes /etc/systemd/system/mirrust.service, then enables and
(re)starts the service, which listens on 0.0.0.0:443 (TCP, and UDP for HTTP/3). Run it again
with other flags to rewrite the unit and restart the service.

  --domain           get a Let's Encrypt certificate for this host name (repeat for up to 4
                     names, or 'auto'); accepts the Let's Encrypt Subscriber Agreement
                     (https://letsencrypt.org/repository/). Conflicts with --cert/--key
  --cert/--key       absolute paths of a PEM certificate chain and private key that systemd
                     reads at start (LoadCredential=); a renewed certificate needs a restart
  --acme-email       contact address for Let's Encrypt (needs --domain)
  --acme-staging     use the Let's Encrypt staging CA (needs --domain)
  --log              request log, a file inside /var/log/mirrust
                     (default /var/log/mirrust/requests.jsonl)
  --max-connections  connections open at once (default: mirrust's own, 1024)
  --dry-run          print every step and the unit text, change nothing; works as any user
                     on any system

uninstall stops and disables the service and removes the unit and the binary. The ACME state
(/var/lib/mirrust) and the logs (/var/log/mirrust) are kept.";

/// Where `install` puts the executable, and where the unit expects it.
const BINARY_PATH: &str = "/usr/local/bin/mirrust";
/// Where `install` writes the unit.
const UNIT_PATH: &str = "/etc/systemd/system/mirrust.service";
/// The unit's name for `systemctl`.
const UNIT_NAME: &str = "mirrust.service";
/// Exists while systemd is the running init system (`sd_booted(3)` checks the same path).
const SYSTEMD_RUNTIME_DIR: &str = "/run/systemd/system";
/// The directory the unit's `LogsDirectory=` creates and the only place the sandbox lets the
/// service write a request log.
const LOG_DIR: &str = "/var/log/mirrust";
/// The request log when `--log` is not given: the one in the unit template.
const DEFAULT_LOG: &str = "/var/log/mirrust/requests.jsonl";
/// The address and port the unit passes to `--listen`.
const LISTEN: &str = "0.0.0.0:443";
/// The unit template, the same file that docs/deploy.md describes.
const TEMPLATE: &str = include_str!("../../../deploy/mirrust.service");

/// How long `install` waits for the service to report `active`.
const START_WAIT: Duration = Duration::from_secs(5);
/// How often it asks while waiting.
const START_POLL: Duration = Duration::from_millis(500);

/// What `install` or `uninstall` was asked to do.
#[derive(Debug)]
pub(crate) enum Request {
    Install(Install),
    Uninstall(Uninstall),
    Help,
}

/// Whether to change the system or only show what would change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Apply,
    DryRun,
}

/// A parsed `mirrust install` command line.
#[derive(Debug)]
pub(crate) struct Install {
    serving: Serving,
    mode: Mode,
}

/// A parsed `mirrust uninstall` command line.
#[derive(Debug)]
pub(crate) struct Uninstall {
    mode: Mode,
}

/// The serving flags that go into the unit. Every string was checked by [`unit_word`].
#[derive(Debug, PartialEq, Eq)]
struct Serving {
    certificate: Certificate,
    log: String,
    max_connections: Option<usize>,
}

/// Where the certificate comes from.
#[derive(Debug, PartialEq, Eq)]
enum Certificate {
    /// `--domain`: mirrust orders and renews it.
    Acme {
        domains: Vec<String>,
        email: Option<String>,
        staging: bool,
    },
    /// `--cert` and `--key`: files that systemd copies for the service at start.
    Files { cert: String, key: String },
}

/// Parses what follows `install` or `uninstall` on the command line.
///
/// # Errors
///
/// Fails for an unknown flag, a flag without its value, a value that cannot be written into a
/// unit, and flag combinations that make no sense (`--cert` without `--key`, `--domain` with
/// `--cert`, `--acme-*` without `--domain`, neither `--domain` nor `--cert`).
pub(crate) fn parse(
    subcommand: &str,
    args: impl IntoIterator<Item = String>,
) -> anyhow::Result<Request> {
    if subcommand == "uninstall" {
        parse_uninstall(args)
    } else {
        parse_install(args)
    }
}

fn parse_uninstall(args: impl IntoIterator<Item = String>) -> anyhow::Result<Request> {
    let mut mode = Mode::Apply;
    for flag in args {
        match flag.as_str() {
            "-h" | "--help" => return Ok(Request::Help),
            "--dry-run" => mode = Mode::DryRun,
            _ => bail!("unknown flag {flag} for mirrust uninstall\n{USAGE}"),
        }
    }
    Ok(Request::Uninstall(Uninstall { mode }))
}

fn parse_install(args: impl IntoIterator<Item = String>) -> anyhow::Result<Request> {
    let mut mode = Mode::Apply;
    let mut domains: Vec<String> = Vec::new();
    let mut email = None;
    let mut staging = false;
    let mut cert = None;
    let mut key = None;
    let mut log = None;
    let mut max_connections = None;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "-h" | "--help" => return Ok(Request::Help),
            "--acme-staging" => {
                staging = true;
                continue;
            }
            "--dry-run" => {
                mode = Mode::DryRun;
                continue;
            }
            _ => {}
        }
        let value = args
            .next()
            .with_context(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--domain" => domains.push(value),
            "--acme-email" => email = Some(unit_word(&check_email(value)?, "--acme-email")?),
            "--cert" => cert = Some(absolute_path(&value, "--cert")?),
            "--key" => key = Some(absolute_path(&value, "--key")?),
            "--log" => log = Some(log_path(&value)?),
            "--max-connections" => {
                max_connections = Some(
                    value
                        .parse()
                        .ok()
                        .filter(|&max: &usize| max > 0)
                        .with_context(|| format!("bad --max-connections {value}"))?,
                );
            }
            _ => bail!(
                "unknown flag {flag} for mirrust install (--listen, --acme-dir and --cors-key \
                 are fixed by the unit; edit {UNIT_PATH} by hand to change them)\n{USAGE}"
            ),
        }
    }
    let certificate = match (domains.is_empty(), cert, key) {
        (false, None, None) => Certificate::Acme {
            domains: check_domains(&domains)?,
            email,
            staging,
        },
        (false, _, _) => {
            bail!("--domain gets its own certificate and conflicts with --cert/--key; use one")
        }
        (true, Some(cert), Some(key)) => {
            if email.is_some() || staging {
                bail!("--acme-email and --acme-staging only mean something with --domain");
            }
            Certificate::Files { cert, key }
        }
        (true, None, None) => {
            if email.is_some() || staging {
                bail!("--acme-email and --acme-staging only mean something with --domain");
            }
            bail!("give --domain NAME to get a certificate, or --cert and --key to bring one")
        }
        (true, _, _) => bail!("--cert and --key go together"),
    };
    Ok(Request::Install(Install {
        serving: Serving {
            certificate,
            log: log.unwrap_or_else(|| DEFAULT_LOG.to_owned()),
            max_connections,
        },
        mode,
    }))
}

/// Validates the `--domain` values: `auto` alone, or up to [`MAX_DOMAINS`] host names. Names
/// are lowercased and repeats dropped, first-given order kept.
fn check_domains(domains: &[String]) -> anyhow::Result<Vec<String>> {
    if domains.iter().any(|name| name == AUTO) {
        ensure!(
            domains.iter().all(|name| name == AUTO),
            "--domain {AUTO} stands for the whole certificate and cannot be combined with other names"
        );
        return Ok(vec![AUTO.to_owned()]);
    }
    let mut names: Vec<String> = Vec::new();
    for name in domains {
        let name = domain::validate(name)?;
        if !names.contains(&name) {
            names.push(name);
        }
    }
    ensure!(
        names.len() <= MAX_DOMAINS,
        "at most {MAX_DOMAINS} --domain names, got {}",
        names.len()
    );
    Ok(names)
}

/// Accepts a value that can stand as one word in an `ExecStart=` or `LoadCredential=` line:
/// no white space, control characters, quotes, backslashes or the characters systemd expands
/// (`$` and `%`).
fn unit_word(value: &str, flag: &str) -> anyhow::Result<String> {
    let bad = |c: char| c.is_whitespace() || c.is_control() || "\"'\\$%;".contains(c);
    ensure!(
        !value.is_empty() && !value.contains(bad),
        "bad {flag} {value:?}: it must not be empty or contain white space, quotes, backslashes, \
         ';', '$' or '%', which a systemd unit would read differently"
    );
    Ok(value.to_owned())
}

/// A certificate or key path: absolute, because the service does not start in your directory.
fn absolute_path(value: &str, flag: &str) -> anyhow::Result<String> {
    ensure!(
        Path::new(value).is_absolute(),
        "bad {flag} {value}: give an absolute path, as the service does not run in this directory"
    );
    unit_word(value, flag)
}

/// The request log: a file below [`LOG_DIR`], the one place the unit's sandbox allows writing
/// to (the service runs as a dynamic user on a read-only file system).
fn log_path(value: &str) -> anyhow::Result<String> {
    let inside = Path::new(value).strip_prefix(LOG_DIR).is_ok_and(|rest| {
        rest.components().count() > 0
            && rest
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
    });
    ensure!(
        inside,
        "bad --log {value}: the unit lets the service write only below {LOG_DIR}, so give a \
         file there such as {DEFAULT_LOG}"
    );
    unit_word(value, "--log")
}

/// The lines of the new `ExecStart=` block, with the trailing backslashes.
fn exec_start(serving: &Serving) -> Vec<String> {
    let mut args = vec![format!("--listen {LISTEN}")];
    match &serving.certificate {
        Certificate::Acme {
            domains,
            email,
            staging,
        } => {
            args.extend(domains.iter().map(|name| format!("--domain {name}")));
            // Set by systemd because of StateDirectory= in the unit.
            args.push("--acme-dir ${STATE_DIRECTORY}".to_owned());
            args.extend(email.iter().map(|email| format!("--acme-email {email}")));
            if *staging {
                args.push("--acme-staging".to_owned());
            }
        }
        Certificate::Files { .. } => {
            // Set by systemd because of LoadCredential= in the unit.
            args.push("--cert ${CREDENTIALS_DIRECTORY}/cert.pem".to_owned());
            args.push("--key ${CREDENTIALS_DIRECTORY}/key.pem".to_owned());
        }
    }
    args.push(format!("--log {}", serving.log));
    args.extend(
        serving
            .max_connections
            .iter()
            .map(|max| format!("--max-connections {max}")),
    );
    let mut lines = vec![format!("ExecStart={BINARY_PATH} \\")];
    let last = args.len() - 1;
    lines.extend(args.into_iter().enumerate().map(|(i, arg)| {
        if i == last {
            format!("    {arg}")
        } else {
            format!("    {arg} \\")
        }
    }));
    lines
}

/// The `LoadCredential=` lines for `--cert`/`--key`, after a comment, or nothing for ACME.
fn credentials(serving: &Serving) -> Vec<String> {
    match &serving.certificate {
        Certificate::Acme { .. } => Vec::new(),
        Certificate::Files { cert, key } => vec![
            String::new(),
            "# The certificate files, read by systemd as root at start and handed to the service"
                .to_owned(),
            "# as private read-only copies; a renewed certificate is used after a restart."
                .to_owned(),
            format!("LoadCredential=cert.pem:{cert}"),
            format!("LoadCredential=key.pem:{key}"),
        ],
    }
}

/// Derives the unit from `template` (`deploy/mirrust.service`): its `ExecStart=` block is
/// replaced by one for `serving`, `LoadCredential=` lines follow it for certificate files, a
/// comment goes on top, and every other line is kept as it is.
///
/// # Errors
///
/// Fails if the template no longer has what this function relies on: exactly one
/// `ExecStart=` for [`BINARY_PATH`], and the `StateDirectory=mirrust` and
/// `LogsDirectory=mirrust` lines that make `${STATE_DIRECTORY}` and the log directory exist.
fn render_unit(template: &str, serving: &Serving) -> anyhow::Result<String> {
    let lines: Vec<&str> = template.lines().collect();
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("ExecStart="))
        .map(|(index, _)| index)
        .collect();
    let [start] = starts[..] else {
        bail!(
            "the unit template has {} ExecStart= lines, expected exactly one",
            starts.len()
        );
    };
    let program = format!("ExecStart={BINARY_PATH}");
    ensure!(
        lines[start].trim_end_matches('\\').trim_end() == program,
        "the unit template's ExecStart= does not start with {BINARY_PATH}: {}",
        lines[start]
    );
    let mut end = start;
    while lines[end].ends_with('\\') {
        end += 1;
        ensure!(
            end < lines.len(),
            "the unit template's ExecStart= ends with a backslash on its last line"
        );
    }
    for needed in ["StateDirectory=mirrust", "LogsDirectory=mirrust"] {
        ensure!(
            lines.contains(&needed),
            "the unit template has no {needed} line"
        );
    }
    let mut unit = vec![
        format!(
            "# Written by `mirrust install` (mirrust {}). Running it again overwrites this file, so",
            env!("CARGO_PKG_VERSION")
        ),
        "# change flags by running it again, not by editing here. The comments below are those of"
            .to_owned(),
        "# deploy/mirrust.service, the template, and address someone editing it by hand."
            .to_owned(),
        String::new(),
    ];
    unit.extend(lines[..start].iter().map(|&line| line.to_owned()));
    unit.extend(exec_start(serving));
    unit.extend(credentials(serving));
    unit.extend(lines[end + 1..].iter().map(|&line| line.to_owned()));
    Ok(unit.join("\n") + "\n")
}

/// What this machine is, for deciding whether `install` can work.
#[derive(Debug)]
struct Host {
    os: &'static str,
    systemd: bool,
    /// The effective user id; `None` where it cannot be read.
    uid: Option<u32>,
}

impl Host {
    fn detect() -> Self {
        Self {
            os: std::env::consts::OS,
            systemd: Path::new(SYSTEMD_RUNTIME_DIR).is_dir(),
            uid: fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|status| parse_effective_uid(&status)),
        }
    }
}

/// The effective user id from the text of `/proc/self/status`: the second number of its `Uid:`
/// line (real, effective, saved, file system).
fn parse_effective_uid(status: &str) -> Option<u32> {
    let ids = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    ids.split_whitespace().nth(1)?.parse().ok()
}

/// Refuses, with a message that says what to do, unless this is Linux with systemd running
/// and the user is root.
fn check_host(host: &Host) -> anyhow::Result<()> {
    ensure!(
        host.os == "linux",
        "mirrust install works on Linux with systemd only, and this is {}; run mirrust directly \
         (see docs/deploy.md)",
        host.os
    );
    ensure!(
        host.systemd,
        "systemd is not running here ({SYSTEMD_RUNTIME_DIR} does not exist); mirrust install \
         needs it. Run mirrust directly or in Docker (see docs/deploy.md)"
    );
    ensure!(
        host.uid == Some(0),
        "mirrust install writes to /usr/local/bin and /etc/systemd/system and starts a service, \
         so it must run as root: sudo mirrust install ..."
    );
    Ok(())
}

/// What a failing `systemctl` call means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    Fatal,
    /// Reported and ignored: for example, stopping a service that was never installed.
    Tolerated,
}

/// One change `install` or `uninstall` makes.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    CopyBinary {
        from: PathBuf,
    },
    WriteUnit,
    RemoveFile {
        path: &'static str,
    },
    Systemctl {
        args: &'static [&'static str],
        failure: Failure,
    },
}

impl Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CopyBinary { from } => write!(
                f,
                "copy {} to {BINARY_PATH}, mode 0755, replacing it atomically (skipped when it is \
                 already that file)",
                from.display()
            ),
            Self::WriteUnit => write!(f, "write {UNIT_PATH}, mode 0644, replacing it atomically"),
            Self::RemoveFile { path } => write!(f, "remove {path} if it exists"),
            Self::Systemctl { args, failure } => {
                write!(f, "run: systemctl {}", args.join(" "))?;
                if *failure == Failure::Tolerated {
                    write!(f, " (a failure is reported and ignored)")?;
                }
                Ok(())
            }
        }
    }
}

/// The steps of `install`, in order. `restart` starts a service that is stopped and restarts
/// one that is running, so running `install` again picks up new flags.
fn install_steps(exe: PathBuf) -> Vec<Step> {
    vec![
        Step::CopyBinary { from: exe },
        Step::WriteUnit,
        Step::Systemctl {
            args: &["daemon-reload"],
            failure: Failure::Fatal,
        },
        Step::Systemctl {
            args: &["enable", UNIT_NAME],
            failure: Failure::Fatal,
        },
        Step::Systemctl {
            args: &["restart", UNIT_NAME],
            failure: Failure::Fatal,
        },
    ]
}

/// The steps of `uninstall`, in order.
fn uninstall_steps() -> Vec<Step> {
    vec![
        Step::Systemctl {
            args: &["disable", "--now", UNIT_NAME],
            failure: Failure::Tolerated,
        },
        Step::RemoveFile { path: UNIT_PATH },
        Step::RemoveFile { path: BINARY_PATH },
        Step::Systemctl {
            args: &["daemon-reload"],
            failure: Failure::Fatal,
        },
    ]
}

/// Runs the command that `request` stands for.
///
/// # Errors
///
/// Fails when a real run is not possible here (not root, not Linux, no systemd), when a file
/// cannot be written, when `systemctl` fails, or when the service is not active at the end.
pub(crate) fn run(request: Request) -> anyhow::Result<()> {
    match request {
        Request::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Request::Install(install) => run_install(&install),
        Request::Uninstall(uninstall) => run_uninstall(&uninstall),
    }
}

fn run_install(install: &Install) -> anyhow::Result<()> {
    let unit = render_unit(TEMPLATE, &install.serving)?;
    let exe = std::env::current_exe().context("finding the running executable")?;
    let steps = install_steps(exe);
    if install.mode == Mode::DryRun {
        print_dry_run(&steps, Some(&unit));
        return Ok(());
    }
    check_host(&Host::detect())?;
    check_certificate_files(&install.serving)?;
    if let Certificate::Acme { .. } = install.serving.certificate {
        println!(
            "--domain means you accept the Let's Encrypt Subscriber Agreement, \
             https://letsencrypt.org/repository/"
        );
    }
    execute(&steps, &unit)?;
    let state = wait_until_active();
    println!("mirrust.service is {state}");
    println!("  installed: {BINARY_PATH}, {UNIT_PATH}");
    println!(
        "  log:       journalctl -u mirrust -f   (request log: {})",
        install.serving.log
    );
    println!("  firewall:  open TCP 443 and UDP 443 (UDP carries HTTP/3); this command changed no");
    println!(
        "             firewall rule, for example: sudo ufw allow 443/tcp && sudo ufw allow 443/udp"
    );
    println!(
        "  change:    run mirrust install again with other flags; remove: sudo mirrust uninstall"
    );
    ensure!(
        state == "active",
        "mirrust.service is {state}, not active; see: systemctl status mirrust.service and \
         journalctl -u mirrust -n 50"
    );
    Ok(())
}

fn run_uninstall(uninstall: &Uninstall) -> anyhow::Result<()> {
    let steps = uninstall_steps();
    if uninstall.mode == Mode::DryRun {
        print_dry_run(&steps, None);
        println!("kept: /var/lib/mirrust (ACME account key and certificates) and /var/log/mirrust");
        return Ok(());
    }
    check_host(&Host::detect())?;
    execute(&steps, "")?;
    println!("removed mirrust.service and {BINARY_PATH}");
    println!(
        "kept: /var/lib/mirrust (ACME account key and certificates) and /var/log/mirrust \
         (request log); with the service's dynamic user the real directories are \
         /var/lib/private/mirrust and /var/log/private/mirrust. Delete them yourself if you no \
         longer need them."
    );
    Ok(())
}

/// Prints the steps, and the unit text if there is one.
fn print_dry_run(steps: &[Step], unit: Option<&str>) {
    println!("dry run: nothing is changed. A real run needs root on Linux with systemd running.");
    for (number, step) in steps.iter().enumerate() {
        println!("{}. {step}", number + 1);
    }
    if let Some(unit) = unit {
        println!("\n{UNIT_PATH} would contain:\n----8<----");
        print!("{unit}");
        println!("----8<----");
    }
}

/// Checks that the certificate and key given with `--cert`/`--key` are files, before anything
/// is changed, so that a typo does not leave a service that cannot start.
fn check_certificate_files(serving: &Serving) -> anyhow::Result<()> {
    if let Certificate::Files { cert, key } = &serving.certificate {
        for path in [cert, key] {
            let metadata = fs::metadata(path).with_context(|| format!("reading {path}"))?;
            ensure!(metadata.is_file(), "{path} is not a file");
        }
    }
    Ok(())
}

fn execute(steps: &[Step], unit: &str) -> anyhow::Result<()> {
    for step in steps {
        println!("{step}");
        match step {
            Step::CopyBinary { from } => copy_binary(from)?,
            Step::WriteUnit => {
                atomic_replace(Path::new(UNIT_PATH), 0o644, |tmp| fs::write(tmp, unit))
                    .with_context(|| format!("writing {UNIT_PATH}"))?;
            }
            Step::RemoveFile { path } => match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).with_context(|| format!("removing {path}")),
            },
            Step::Systemctl { args, failure } => {
                let result = systemctl(args);
                match (result, failure) {
                    (Ok(()), _) => {}
                    (Err(error), Failure::Tolerated) => println!("  ignored: {error:#}"),
                    (Err(error), Failure::Fatal) => return Err(error),
                }
            }
        }
    }
    Ok(())
}

fn systemctl(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .context("running systemctl")?;
    ensure!(
        status.success(),
        "systemctl {} failed: {status}",
        args.join(" ")
    );
    Ok(())
}

/// Copies the executable to [`BINARY_PATH`] unless it already is that file.
fn copy_binary(from: &Path) -> anyhow::Result<()> {
    let to = Path::new(BINARY_PATH);
    if let (Ok(from), Ok(to)) = (from.canonicalize(), to.canonicalize())
        && from == to
    {
        println!("  already in place");
        return Ok(());
    }
    if let Some(dir) = to.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    atomic_replace(to, 0o755, |tmp| fs::copy(from, tmp).map(|_| ()))
        .with_context(|| format!("copying {} to {BINARY_PATH}", from.display()))
}

/// Replaces `to` without a moment in which it is missing or half written: `write` fills a
/// temporary file next to it, which gets `mode` and is then renamed over `to`.
fn atomic_replace(
    to: &Path,
    mode: u32,
    write: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let name = to
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let tmp = to.with_file_name(format!(".{name}.tmp"));
    let result = write(&tmp)
        .and_then(|()| set_mode(&tmp, mode))
        .and_then(|()| fs::rename(&tmp, to));
    if result.is_err() {
        // Best effort: the error that matters is the one returned.
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// File modes mean nothing here, and a real run is refused before it gets this far.
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// Asks `systemctl is-active` until it says `active` or [`START_WAIT`] has passed, and returns
/// the last answer.
fn wait_until_active() -> String {
    let mut waited = Duration::ZERO;
    loop {
        let state = Command::new("systemctl")
            .args(["is-active", UNIT_NAME])
            .output()
            .map_or_else(
                |error| format!("unknown ({error})"),
                |output| String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            );
        if state == "active" || waited >= START_WAIT {
            return state;
        }
        thread::sleep(START_POLL);
        waited += START_POLL;
    }
}

// The install command is for Linux with systemd; its tests use Unix paths and are skipped elsewhere.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn args(args: &[&str]) -> Vec<String> {
        args.iter().map(|&arg| arg.to_owned()).collect()
    }

    fn install(flags: &[&str]) -> anyhow::Result<Install> {
        match parse("install", args(flags))? {
            Request::Install(install) => Ok(install),
            other => bail!("not an install: {other:?}"),
        }
    }

    fn error(flags: &[&str]) -> String {
        format!("{:#}", install(flags).expect_err("should be refused"))
    }

    fn unit(flags: &[&str]) -> String {
        let install = install(flags).expect("valid flags");
        render_unit(TEMPLATE, &install.serving).expect("renders")
    }

    /// The `ExecStart=` block of a unit, as one string with the continuation lines joined.
    fn exec_block(unit: &str) -> String {
        let mut block = Vec::new();
        let mut inside = false;
        for line in unit.lines() {
            if line.starts_with("ExecStart=") {
                inside = true;
            }
            if inside {
                block.push(line.trim_end_matches('\\').trim());
                if !line.ends_with('\\') {
                    break;
                }
            }
        }
        block.join(" ")
    }

    #[test]
    fn domain_alone_gives_the_documented_unit() {
        let unit = unit(&["--domain", "mirror.example.com"]);
        assert_eq!(
            exec_block(&unit),
            "ExecStart=/usr/local/bin/mirrust --listen 0.0.0.0:443 --domain mirror.example.com \
             --acme-dir ${STATE_DIRECTORY} --log /var/log/mirrust/requests.jsonl"
        );
        assert!(!unit.contains("LoadCredential="), "{unit}");
    }

    #[test]
    fn the_embedded_template_has_the_same_exec_start() {
        // What `install --domain mirror.example.com` writes is what the template says: the
        // same flags, in the same order.
        let ours = unit(&["--domain", "mirror.example.com"]);
        assert_eq!(exec_block(&ours), exec_block(TEMPLATE));
    }

    #[test]
    fn everything_but_the_exec_start_block_is_the_template() {
        for flags in [
            &["--domain", "mirror.example.com"][..],
            &["--cert", "/etc/ssl/c.pem", "--key", "/etc/ssl/k.pem"],
        ] {
            let ours = unit(flags);
            let ours: Vec<&str> = ours.lines().collect();
            let template: Vec<&str> = TEMPLATE.lines().collect();
            // The comment on top and the credentials are added, the block is replaced; the
            // line before the block and the line after it are the template's.
            let template_start = template
                .iter()
                .position(|line| line.starts_with("ExecStart="))
                .expect("template has ExecStart");
            let our_start = ours
                .iter()
                .position(|line| line.starts_with("ExecStart="))
                .expect("unit has ExecStart");
            assert_eq!(&ours[4..our_start], &template[..template_start]);
            let tail = &template[template
                .iter()
                .position(|line| *line == "KillSignal=SIGINT")
                .expect("KillSignal")..];
            assert!(ours.ends_with(tail), "the rest of the template is kept");
        }
    }

    #[test]
    fn every_flag_reaches_the_unit() {
        let unit = unit(&[
            "--domain",
            "A.example.com",
            "--domain",
            "b.example.com",
            "--domain",
            "a.example.com",
            "--acme-email",
            "admin@example.com",
            "--acme-staging",
            "--log",
            "/var/log/mirrust/other.jsonl",
            "--max-connections",
            "2048",
        ]);
        assert_eq!(
            exec_block(&unit),
            "ExecStart=/usr/local/bin/mirrust --listen 0.0.0.0:443 --domain a.example.com \
             --domain b.example.com --acme-dir ${STATE_DIRECTORY} --acme-email admin@example.com \
             --acme-staging --log /var/log/mirrust/other.jsonl --max-connections 2048"
        );
    }

    #[test]
    fn certificate_files_use_load_credential() {
        let unit = unit(&["--cert", "/etc/ssl/c.pem", "--key", "/etc/ssl/k.pem"]);
        assert_eq!(
            exec_block(&unit),
            "ExecStart=/usr/local/bin/mirrust --listen 0.0.0.0:443 \
             --cert ${CREDENTIALS_DIRECTORY}/cert.pem --key ${CREDENTIALS_DIRECTORY}/key.pem \
             --log /var/log/mirrust/requests.jsonl"
        );
        let lines: Vec<&str> = unit.lines().collect();
        let service = lines
            .iter()
            .position(|l| *l == "[Service]")
            .expect("[Service]");
        let install = lines
            .iter()
            .position(|l| *l == "[Install]")
            .expect("[Install]");
        for line in [
            "LoadCredential=cert.pem:/etc/ssl/c.pem",
            "LoadCredential=key.pem:/etc/ssl/k.pem",
        ] {
            let at = lines.iter().position(|l| *l == line).expect(line);
            assert!(service < at && at < install, "{line} is in [Service]");
        }
        assert!(
            !unit.contains("--domain mirror"),
            "no domain in the unit's ExecStart"
        );
        assert!(!exec_block(&unit).contains("--acme"), "no ACME flag");
    }

    #[test]
    fn the_unit_says_who_wrote_it() {
        let unit = unit(&["--domain", "mirror.example.com"]);
        assert!(
            unit.starts_with("# Written by `mirrust install` (mirrust "),
            "{unit}"
        );
        assert!(unit.ends_with('\n'));
    }

    #[test]
    fn a_template_that_changed_is_refused() {
        let serving = install(&["--domain", "mirror.example.com"])
            .expect("valid")
            .serving;
        let broken = |template: String| {
            format!(
                "{:#}",
                render_unit(&template, &serving).expect_err("refused")
            )
        };
        let message = broken(TEMPLATE.replace("ExecStart=", "ExecStartPre="));
        assert!(message.contains("0 ExecStart= lines"), "{message}");
        let message = broken(format!("{TEMPLATE}\nExecStart=/bin/true\n"));
        assert!(message.contains("2 ExecStart= lines"), "{message}");
        let message =
            broken(TEMPLATE.replace("ExecStart=/usr/local/bin/mirrust", "ExecStart=/opt/mirrust"));
        assert!(
            message.contains("does not start with /usr/local/bin/mirrust"),
            "{message}"
        );
        let message = broken(TEMPLATE.replace("StateDirectory=mirrust\n", ""));
        assert!(
            message.contains("no StateDirectory=mirrust line"),
            "{message}"
        );
        let message = broken(TEMPLATE.replace("LogsDirectory=mirrust\n", ""));
        assert!(
            message.contains("no LogsDirectory=mirrust line"),
            "{message}"
        );
        let message = broken("[Service]\nStateDirectory=mirrust\nLogsDirectory=mirrust\nExecStart=/usr/local/bin/mirrust \\".to_owned());
        assert!(message.contains("last line"), "{message}");
    }

    #[test]
    fn flags_that_make_no_sense_are_refused() {
        assert!(error(&[]).contains("give --domain NAME"));
        assert!(error(&["--cert", "/c.pem"]).contains("--cert and --key go together"));
        assert!(error(&["--key", "/k.pem"]).contains("--cert and --key go together"));
        assert!(
            error(&[
                "--domain",
                "a.example.com",
                "--cert",
                "/c.pem",
                "--key",
                "/k.pem"
            ])
            .contains("conflicts with --cert/--key")
        );
        assert!(
            error(&["--domain", "a.example.com", "--cert", "/c.pem"])
                .contains("conflicts with --cert/--key")
        );
        for extra in [&["--acme-staging"][..], &["--acme-email", "a@example.com"]] {
            let mut flags = vec!["--cert", "/c.pem", "--key", "/k.pem"];
            flags.extend(extra);
            assert!(
                error(&flags).contains("only mean something with --domain"),
                "{flags:?}"
            );
        }
        assert!(error(&["--acme-staging"]).contains("only mean something with --domain"));
    }

    #[test]
    fn bad_values_are_refused() {
        assert!(error(&["--domain", "nobody"]).contains("bad --domain"));
        assert!(
            error(&["--domain", "auto", "--domain", "a.example.com"])
                .contains("cannot be combined")
        );
        assert!(
            error(&[
                "--domain", "a.com", "--domain", "b.com", "--domain", "c.com", "--domain", "d.com",
                "--domain", "e.com"
            ])
            .contains("at most 4")
        );
        assert!(
            error(&["--domain", "a.example.com", "--acme-email", "nobody"])
                .contains("bad --acme-email")
        );
        assert!(
            error(&[
                "--domain",
                "a.example.com",
                "--acme-email",
                "a$b@example.com"
            ])
            .contains("bad --acme-email")
        );
        assert!(
            error(&["--domain", "a.example.com", "--max-connections", "0"])
                .contains("bad --max-connections")
        );
        assert!(
            error(&["--domain", "a.example.com", "--max-connections", "x"])
                .contains("bad --max-connections")
        );
        assert!(error(&["--cert", "c.pem", "--key", "/k.pem"]).contains("absolute path"));
        assert!(error(&["--cert", "/a b/c.pem", "--key", "/k.pem"]).contains("white space"));
        assert!(error(&["--cert", "/a%h/c.pem", "--key", "/k.pem"]).contains("'%'"));
        assert!(error(&["--domain"]).contains("--domain needs a value"));
        assert!(error(&["--listen", "0.0.0.0:80"]).contains("unknown flag --listen"));
    }

    #[test]
    fn the_log_stays_inside_the_log_directory() {
        for bad in [
            "requests.jsonl",
            "/tmp/requests.jsonl",
            "/var/log/mirrust",
            "/var/log/mirrust/",
            "/var/log/mirrust/../x.jsonl",
            "/var/log/mirrustx/x.jsonl",
            "/var/log/mirrust/a b.jsonl",
        ] {
            let message = error(&["--domain", "a.example.com", "--log", bad]);
            assert!(message.contains("bad --log"), "{bad}: {message}");
        }
        for good in ["/var/log/mirrust/x.jsonl", "/var/log/mirrust/sub/x.jsonl"] {
            assert!(
                install(&["--domain", "a.example.com", "--log", good]).is_ok(),
                "{good}"
            );
        }
    }

    #[test]
    fn help_and_dry_run_are_flags_of_both_commands() {
        assert!(matches!(
            parse("install", args(&["--help"])),
            Ok(Request::Help)
        ));
        assert!(matches!(
            parse("uninstall", args(&["-h"])),
            Ok(Request::Help)
        ));
        assert_eq!(
            install(&["--domain", "a.example.com", "--dry-run"])
                .expect("valid")
                .mode,
            Mode::DryRun
        );
        assert_eq!(
            install(&["--domain", "a.example.com"]).expect("valid").mode,
            Mode::Apply
        );
        match parse("uninstall", args(&["--dry-run"])).expect("valid") {
            Request::Uninstall(uninstall) => assert_eq!(uninstall.mode, Mode::DryRun),
            other => panic!("not an uninstall: {other:?}"),
        }
        let message = format!(
            "{:#}",
            parse("uninstall", args(&["--domain", "a.example.com"])).expect_err("refused")
        );
        assert!(
            message.contains("unknown flag --domain for mirrust uninstall"),
            "{message}"
        );
    }

    #[test]
    fn the_host_checks_say_what_to_do() {
        let good = Host {
            os: "linux",
            systemd: true,
            uid: Some(0),
        };
        assert!(check_host(&good).is_ok());
        let message = |host: Host| format!("{:#}", check_host(&host).expect_err("refused"));
        let mac = message(Host {
            os: "macos",
            ..good_host()
        });
        assert!(
            mac.contains("Linux with systemd only") && mac.contains("this is macos"),
            "{mac}"
        );
        let no_systemd = message(Host {
            systemd: false,
            ..good_host()
        });
        assert!(
            no_systemd.contains("/run/systemd/system does not exist"),
            "{no_systemd}"
        );
        let user = message(Host {
            uid: Some(1000),
            ..good_host()
        });
        assert!(user.contains("must run as root"), "{user}");
        let unknown = message(Host {
            uid: None,
            ..good_host()
        });
        assert!(unknown.contains("must run as root"), "{unknown}");
        // The OS is checked first, so a Mac user is not told to use sudo.
        let both = message(Host {
            os: "macos",
            systemd: false,
            uid: Some(501),
        });
        assert!(both.contains("this is macos"), "{both}");
    }

    fn good_host() -> Host {
        Host {
            os: "linux",
            systemd: true,
            uid: Some(0),
        }
    }

    #[test]
    fn the_effective_uid_is_the_second_number() {
        let status =
            "Name:\tmirrust\nUmask:\t0022\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_effective_uid(status), Some(0));
        assert_eq!(
            parse_effective_uid("Uid:\t0\t1000\t1000\t1000\n"),
            Some(1000)
        );
        assert_eq!(parse_effective_uid("Name:\tx\n"), None);
        assert_eq!(parse_effective_uid("Uid:\t0\n"), None);
        assert_eq!(parse_effective_uid("Uid:\t0\tx\n"), None);
    }

    #[test]
    fn install_runs_the_documented_commands_in_order() {
        let steps = install_steps(PathBuf::from("/tmp/mirrust"));
        let text: Vec<String> = steps.iter().map(ToString::to_string).collect();
        assert_eq!(text.len(), 5);
        assert!(
            text[0].starts_with("copy /tmp/mirrust to /usr/local/bin/mirrust, mode 0755"),
            "{}",
            text[0]
        );
        assert_eq!(
            text[1],
            "write /etc/systemd/system/mirrust.service, mode 0644, replacing it atomically"
        );
        assert_eq!(text[2], "run: systemctl daemon-reload");
        assert_eq!(text[3], "run: systemctl enable mirrust.service");
        assert_eq!(text[4], "run: systemctl restart mirrust.service");
    }

    #[test]
    fn uninstall_tolerates_a_service_that_is_not_there() {
        let steps = uninstall_steps();
        assert_eq!(
            steps.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [
                "run: systemctl disable --now mirrust.service (a failure is reported and ignored)",
                "remove /etc/systemd/system/mirrust.service if it exists",
                "remove /usr/local/bin/mirrust if it exists",
                "run: systemctl daemon-reload",
            ]
        );
    }

    #[test]
    fn atomic_replace_swaps_the_file_and_leaves_no_temporary() {
        let dir = std::env::temp_dir().join(format!("mirrust-install-test-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create the test directory");
        let target = dir.join("file");
        fs::write(&target, "old").expect("seed");
        atomic_replace(&target, 0o644, |tmp| fs::write(tmp, "new")).expect("replace");
        assert_eq!(fs::read_to_string(&target).expect("read"), "new");
        let failed = atomic_replace(&target, 0o644, |tmp| {
            fs::write(tmp, "half")?;
            Err(io::Error::other("stop"))
        });
        assert!(failed.is_err());
        assert_eq!(
            fs::read_to_string(&target).expect("read"),
            "new",
            "the old file survives"
        );
        let names: Vec<_> = fs::read_dir(&dir)
            .expect("list")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names, ["file"], "no temporary file is left");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o644);
        }
        fs::remove_dir_all(&dir).expect("clean up");
    }
}
