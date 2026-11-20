//! `mirrust probe`: runs a command against a throwaway server on loopback and prints how the
//! command's connections looked.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, io, process};

use anyhow::{Context, bail};
use server::{ProbeServer, Seen};

/// The exit code for a usage error or when the probe could not start or run the command.
pub(crate) const EXIT_USAGE: i32 = 2;
/// The exit code when `--fail-under` is not met.
const EXIT_SCORE: i32 = 3;
/// The exit code when the command was killed by a signal and has no exit code.
const EXIT_SIGNALLED: i32 = 1;

/// How many directory names are tried before giving up on a temporary directory.
const TEMP_DIR_ATTEMPTS: u32 = 16;

pub(crate) const USAGE: &str = "usage: mirrust probe [--fail-under N] [--json] -- COMMAND [ARGS...]

Runs COMMAND while a throwaway mirrust server listens on 127.0.0.1 (a random port, TCP and
HTTP/3 over UDP, a self-signed certificate), then prints on stderr how each connection the
server saw looked. The command gets

  MIRRUST_URL      https://127.0.0.1:PORT
  MIRRUST_CACERT   path of the certificate (PEM) to trust; removed when probe ends

and keeps stdin, stdout and stderr. Nothing about the connections is written to disk.

  --fail-under N   exit 3 when the lowest audit score is below N (0 to 100), or when no
                   connection reached the server
  --json           print one JSON object per connection per line (the body of /api/all)
                   instead of the text reports; lines starting with 'mirrust probe:' are
                   messages, not JSON
  -h, --help       print this text and exit

Exit codes: the command's own non-zero code (1 when a signal ended it); 2 for a usage error
or when the probe cannot start; 3 when --fail-under is not met (the command's code wins when
both fail); otherwise 0.";

/// How the report on stderr is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Text,
    Json,
}

/// What `mirrust probe` was asked to do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Request {
    fail_under: Option<u8>,
    format: Format,
    program: String,
    args: Vec<String>,
}

/// What the arguments after `probe` ask for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    Help,
    Run(Request),
}

/// Reads the arguments that follow `probe`.
///
/// # Errors
///
/// Fails for an unknown flag, a flag without its value, an out-of-range `--fail-under`, a
/// missing `--` or a missing command. `--listen`, `--cert`, `--key` and `--domain` are
/// refused with their own message: the probe server always listens on loopback with its own
/// certificate.
pub(crate) fn parse(args: impl IntoIterator<Item = String>) -> anyhow::Result<Parsed> {
    let mut fail_under = None;
    let mut format = Format::Text;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--json" => format = Format::Json,
            "--fail-under" => {
                let value = args
                    .next()
                    .with_context(|| format!("{flag} needs a value\n{USAGE}"))?;
                fail_under = Some(
                    value
                        .parse()
                        .ok()
                        .filter(|&score| score <= 100)
                        .with_context(|| {
                            format!("bad --fail-under {value}: expected an integer from 0 to 100")
                        })?,
                );
            }
            "--listen" | "--cert" | "--key" | "--domain" => bail!(
                "{flag} is not accepted by probe: it listens on 127.0.0.1 with a certificate of \
                 its own\n{USAGE}"
            ),
            "--" => {
                let program = args
                    .next()
                    .with_context(|| format!("no command after --\n{USAGE}"))?;
                return Ok(Parsed::Run(Request {
                    fail_under,
                    format,
                    program,
                    args: args.collect(),
                }));
            }
            _ if flag.starts_with('-') => bail!("unknown flag {flag} for mirrust probe\n{USAGE}"),
            _ => bail!("expected -- before the command, got {flag}\n{USAGE}"),
        }
    }
    bail!("no command: put it after --\n{USAGE}")
}

/// Runs the probe and returns the exit code; every guard is dropped by then.
pub(crate) async fn run(request: Request) -> i32 {
    match probe(request).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("mirrust probe: {error:#}");
            EXIT_USAGE
        }
    }
}

async fn probe(request: Request) -> anyhow::Result<i32> {
    let server = ProbeServer::start()
        .await
        .context("starting the probe server")?;
    let dir = TempDir::create().context("creating a temporary directory")?;
    let cacert = dir.path().join("cacert.pem");
    fs::write(&cacert, server.cert_pem())
        .with_context(|| format!("writing {}", cacert.display()))?;

    let mut command = Command::new(&request.program);
    command
        .args(&request.args)
        .env("MIRRUST_URL", format!("https://{}", server.addr()))
        .env("MIRRUST_CACERT", &cacert);
    // Ctrl-C goes to the command too, as it shares the terminal. Probe outlives it, to print
    // what was seen and remove the directory, instead of dying with it.
    let interrupt = tokio::spawn(tokio::signal::ctrl_c());
    tokio::task::yield_now().await;
    let status = tokio::task::spawn_blocking(move || command.status())
        .await
        .context("waiting for the command")?
        .with_context(|| format!("cannot run {}", request.program))?;
    interrupt.abort();

    let seen = server.stop().await.context("the probe server failed")?;
    drop(dir);
    let scores: Vec<u8> = seen.visits.iter().map(|visit| visit.score).collect();
    eprint!("{}", render(&seen, request.format));
    if let Some(message) = score_message(&scores, request.fail_under) {
        eprintln!("mirrust probe: {message}");
    }
    Ok(exit_code(status.code(), &scores, request.fail_under))
}

/// The report for stderr: a summary and the text report of each connection, or one JSON object
/// per connection per line.
fn render(seen: &Seen, format: Format) -> String {
    let mut out = String::new();
    let lowest = seen.visits.iter().map(|visit| visit.score).min();
    match (lowest, format) {
        (None, _) => out.push_str("mirrust probe: no connection reached the probe server\n"),
        (Some(lowest), Format::Text) => {
            let count = seen.visits.len();
            let noun = if count == 1 {
                "connection"
            } else {
                "connections"
            };
            writeln!(
                out,
                "mirrust probe: {count} {noun} seen, lowest audit score {lowest}/100"
            )
            .expect("writing to a String cannot fail");
        }
        (Some(_), Format::Json) => {}
    }
    for visit in &seen.visits {
        match format {
            Format::Text => {
                out.push('\n');
                out.push_str(&visit.text);
            }
            Format::Json => {
                out.push_str(&visit.json);
                out.push('\n');
            }
        }
    }
    if seen.failed_handshakes > 0 {
        writeln!(
            out,
            "mirrust probe: {} TLS handshake(s) over TCP failed; does the client trust \
             MIRRUST_CACERT?",
            seen.failed_handshakes
        )
        .expect("writing to a String cannot fail");
    }
    out
}

/// Whether `--fail-under` is met by the scores of the connections seen.
#[derive(Debug, PartialEq, Eq)]
enum ScoreCheck {
    /// No `--fail-under`.
    NotAsked,
    Met,
    TooLow {
        lowest: u8,
        min: u8,
    },
    NoConnection {
        min: u8,
    },
}

fn score_check(scores: &[u8], fail_under: Option<u8>) -> ScoreCheck {
    let Some(min) = fail_under else {
        return ScoreCheck::NotAsked;
    };
    match scores.iter().min() {
        None => ScoreCheck::NoConnection { min },
        Some(&lowest) if lowest < min => ScoreCheck::TooLow { lowest, min },
        Some(_) => ScoreCheck::Met,
    }
}

/// Why `--fail-under` is not met; `None` when it is met or was not given.
fn score_message(scores: &[u8], fail_under: Option<u8>) -> Option<String> {
    match score_check(scores, fail_under) {
        ScoreCheck::TooLow { lowest, min } => Some(format!(
            "lowest audit score {lowest} is below --fail-under {min}"
        )),
        ScoreCheck::NoConnection { min } => Some(format!(
            "--fail-under {min} needs a connection, and none reached the probe server"
        )),
        ScoreCheck::NotAsked | ScoreCheck::Met => None,
    }
}

/// The exit code of a probe run. `child` is the command's exit code, `None` when a signal
/// ended it. A command that failed decides the code, whatever the scores say; otherwise a
/// missed `--fail-under` is 3.
fn exit_code(child: Option<i32>, scores: &[u8], fail_under: Option<u8>) -> i32 {
    match child {
        None => EXIT_SIGNALLED,
        Some(code) if code != 0 => code,
        Some(_) => match score_check(scores, fail_under) {
            ScoreCheck::TooLow { .. } | ScoreCheck::NoConnection { .. } => EXIT_SCORE,
            ScoreCheck::NotAsked | ScoreCheck::Met => 0,
        },
    }
}

/// A new directory in the system's temporary directory, removed with its contents on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn create() -> io::Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.subsec_nanos());
        for attempt in 0..TEMP_DIR_ATTEMPTS {
            let name = format!("mirrust-probe-{}-{nanos}-{attempt}", process::id());
            let path = env::temp_dir().join(name);
            // Fails when the name exists, so a directory planted there is never reused.
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "no unused name for a temporary directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best effort: a directory left behind holds only a public certificate.
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strs(args: &[&str]) -> anyhow::Result<Parsed> {
        parse(args.iter().map(|&arg| arg.to_owned()))
    }

    fn request(args: &[&str]) -> Request {
        match parse_strs(args).expect("valid") {
            Parsed::Run(request) => request,
            Parsed::Help => panic!("help for {args:?}"),
        }
    }

    fn error(args: &[&str]) -> String {
        format!("{:#}", parse_strs(args).expect_err("should be refused"))
    }

    #[test]
    fn the_command_follows_the_double_dash() {
        assert_eq!(
            request(&["--", "curl", "-s", "--", "x"]),
            Request {
                fail_under: None,
                format: Format::Text,
                program: "curl".to_owned(),
                args: vec!["-s".to_owned(), "--".to_owned(), "x".to_owned()],
            }
        );
    }

    #[test]
    fn flags_come_before_the_double_dash_in_any_order() {
        let first = request(&["--fail-under", "70", "--json", "--", "client"]);
        let second = request(&["--json", "--fail-under", "70", "--", "client"]);
        assert_eq!(first, second);
        assert_eq!(first.fail_under, Some(70));
        assert_eq!(first.format, Format::Json);
        // A flag after `--` belongs to the command.
        let after = request(&["--", "client", "--json", "--fail-under", "7"]);
        assert_eq!(after.fail_under, None);
        assert_eq!(after.args, ["--json", "--fail-under", "7"]);
    }

    #[test]
    fn help_wins_before_the_double_dash_only() {
        for flag in ["-h", "--help"] {
            assert_eq!(parse_strs(&[flag]).expect("help"), Parsed::Help);
            assert_eq!(
                parse_strs(&["--json", flag, "--", "x"]).expect("help"),
                Parsed::Help
            );
        }
        assert_eq!(request(&["--", "x", "--help"]).args, ["--help"]);
    }

    #[test]
    fn fail_under_takes_an_integer_from_0_to_100() {
        for (value, expected) in [("0", 0), ("100", 100), ("55", 55)] {
            assert_eq!(
                request(&["--fail-under", value, "--", "x"]).fail_under,
                Some(expected)
            );
        }
        for bad in ["101", "-1", "abc", "", "1.5", "256"] {
            let message = error(&["--fail-under", bad, "--", "x"]);
            assert!(message.contains("bad --fail-under"), "{bad}: {message}");
        }
        assert!(error(&["--fail-under"]).contains("--fail-under needs a value"));
    }

    #[test]
    fn the_server_flags_are_not_accepted() {
        for flag in ["--listen", "--cert", "--key", "--domain"] {
            let message = error(&[flag, "x", "--", "client"]);
            assert!(message.contains("is not accepted by probe"), "{message}");
            assert!(message.contains(flag), "{message}");
        }
    }

    #[test]
    fn usage_errors_say_what_is_wrong() {
        assert!(error(&[]).contains("no command"));
        assert!(error(&["--json"]).contains("no command"));
        assert!(error(&["--"]).contains("no command after --"));
        assert!(error(&["--json", "--"]).contains("no command after --"));
        assert!(error(&["curl", "-s"]).contains("expected -- before the command, got curl"));
        assert!(error(&["--bogus", "--", "x"]).contains("unknown flag --bogus"));
        assert!(error(&["-x"]).contains("unknown flag -x"));
        for args in [&["--bogus"][..], &["curl"]] {
            assert!(error(args).contains("usage: mirrust probe"), "{args:?}");
        }
    }

    #[test]
    fn the_exit_code_follows_the_command_then_the_scores() {
        // (command, scores, --fail-under, expected)
        type Case = (Option<i32>, &'static [u8], Option<u8>, i32);
        let cases: [Case; 14] = [
            (Some(0), &[90], None, 0),
            (Some(0), &[], None, 0),
            (Some(0), &[90, 80], Some(80), 0),
            (Some(0), &[90, 79], Some(80), EXIT_SCORE),
            (Some(0), &[100], Some(0), 0),
            (Some(0), &[0], Some(0), 0),
            (Some(0), &[], Some(1), EXIT_SCORE),
            (Some(0), &[], Some(0), EXIT_SCORE),
            (Some(7), &[90], None, 7),
            (Some(7), &[10], Some(50), 7),
            (Some(7), &[], Some(50), 7),
            (None, &[90], None, EXIT_SIGNALLED),
            (None, &[10], Some(50), EXIT_SIGNALLED),
            (Some(3), &[90], Some(50), 3),
        ];
        for (child, scores, fail_under, expected) in cases {
            assert_eq!(
                exit_code(child, scores, fail_under),
                expected,
                "child {child:?}, scores {scores:?}, --fail-under {fail_under:?}"
            );
        }
    }

    #[test]
    fn a_missed_threshold_is_explained() {
        assert_eq!(score_message(&[90], None), None);
        assert_eq!(score_message(&[90, 60], Some(60)), None);
        let low = score_message(&[90, 59], Some(60)).expect("too low");
        assert!(
            low.contains("lowest audit score 59 is below --fail-under 60"),
            "{low}"
        );
        let none = score_message(&[], Some(1)).expect("no connection");
        assert!(none.contains("none reached the probe server"), "{none}");
    }

    fn visit(score: u8) -> server::Visit {
        server::Visit {
            score,
            text: format!("report {score}\n"),
            json: format!("{{\"score\":{score}}}"),
        }
    }

    #[test]
    fn the_report_has_a_summary_and_one_block_per_connection() {
        let seen = Seen {
            visits: vec![visit(90), visit(70)],
            failed_handshakes: 0,
        };
        assert_eq!(
            render(&seen, Format::Text),
            "mirrust probe: 2 connections seen, lowest audit score 70/100\n\nreport 90\n\nreport 70\n"
        );
        assert_eq!(
            render(&seen, Format::Json),
            "{\"score\":90}\n{\"score\":70}\n"
        );
    }

    #[test]
    fn nothing_seen_and_failed_handshakes_are_mentioned() {
        let seen = Seen {
            visits: Vec::new(),
            failed_handshakes: 2,
        };
        for format in [Format::Text, Format::Json] {
            let text = render(&seen, format);
            assert!(
                text.starts_with("mirrust probe: no connection reached the probe server\n"),
                "{text}"
            );
            assert!(
                text.contains("2 TLS handshake(s) over TCP failed"),
                "{text}"
            );
        }
    }
}
