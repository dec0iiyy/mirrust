//! `mirrust probe`, run as a process.
//!
//! The command probe runs is this test binary itself, started at `probe_client` with
//! `MIRRUST_TEST_CLIENT` set: a rustls client that trusts `MIRRUST_CACERT` and asks
//! `MIRRUST_URL` for `/`. Without that variable `probe_client` does nothing, so a plain test run
//! passes it by.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::Value;

/// What the client does: `get` asks for `/` and prints [`MARKER`], `fail` exits with code 7,
/// anything else (or nothing) makes no connection.
const CLIENT_MODE: &str = "MIRRUST_TEST_CLIENT";
/// Starts the line the client prints on stdout.
const MARKER: &str = "client-got";

#[test]
fn probe_client() {
    match std::env::var(CLIENT_MODE).as_deref() {
        Ok("get") => get_root(),
        Ok("fail") => std::process::exit(7),
        _ => {}
    }
}

/// Asks `MIRRUST_URL` for `/`, trusting only `MIRRUST_CACERT`, and prints the status line and
/// the path of the certificate file.
fn get_root() {
    let url = std::env::var("MIRRUST_URL").expect("probe sets MIRRUST_URL");
    let cacert = std::env::var("MIRRUST_CACERT").expect("probe sets MIRRUST_CACERT");
    let addr = url.strip_prefix("https://").expect("an https URL");
    let ip = addr.split_once(':').expect("ADDR:PORT").0;

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&cacert).expect("the certificate file exists") {
        roots.add(cert.expect("valid PEM")).expect("a usable root");
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // An IP address: the certificate must name 127.0.0.1 for this to verify.
    let name = ServerName::try_from(ip.to_owned()).expect("an IP address");
    let conn = ClientConnection::new(Arc::new(config), name).expect("client connection");
    let mut tls = StreamOwned::new(conn, TcpStream::connect(addr).expect("connect"));
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: probe-test/1\r\n\r\n")
        .expect("send the request");
    let mut response = String::new();
    // The server closes after one response; a missing close_notify is not this test's concern.
    let _ = tls.read_to_string(&mut response);
    let status = response.lines().next().expect("a status line");
    assert_eq!(status, "HTTP/1.1 200 OK");
    println!("{MARKER} {status} cacert={cacert}");
}

/// Runs `mirrust probe <flags> -- <this test binary as the client>` with the client in `mode`
/// (`None` makes no connection).
fn probe(flags: &[&str], mode: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mirrust"));
    command.arg("probe").args(flags).args([
        "--",
        std::env::current_exe()
            .expect("the test binary's path")
            .to_str()
            .expect("a UTF-8 path"),
        "--exact",
        "probe_client",
        "--nocapture",
    ]);
    if let Some(mode) = mode {
        command.env(CLIENT_MODE, mode);
    }
    command.output().expect("run mirrust probe")
}

fn mirrust(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mirrust"))
        .args(args)
        .output()
        .expect("run mirrust")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn probe_audits_the_client_and_leaves_its_stdout_alone() {
    let output = probe(&["--fail-under", "1"], Some("get"));
    let (stdout, stderr) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(0), "{stderr}");

    // The client's own output, and nothing from the server: no listening line, no request line.
    let line = stdout
        .lines()
        .find(|line| line.starts_with(MARKER))
        .unwrap_or_else(|| panic!("the client's line is missing from\n{stdout}"));
    assert!(
        line.starts_with("client-got HTTP/1.1 200 OK cacert="),
        "{line}"
    );
    for server_output in ["listening on", " GET ", "mirrust probe"] {
        assert!(!stdout.contains(server_output), "{server_output}: {stdout}");
    }

    assert!(
        stderr.starts_with("mirrust probe: 1 connection seen, lowest audit score "),
        "{stderr}"
    );
    assert!(stderr.contains("\nAUDIT  "), "{stderr}");
    assert!(stderr.contains("FINGERPRINTS"), "{stderr}");

    // The certificate file existed while the client ran and is gone now.
    let cacert = line.split_once("cacert=").expect("the path").1;
    assert!(!Path::new(cacert).exists(), "{cacert} is still there");
    assert!(!Path::new(cacert).parent().expect("a directory").exists());
}

#[test]
fn json_prints_one_object_per_connection() {
    let output = probe(&["--json"], Some("get"));
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 1, "{stderr}");
    let report: Value = serde_json::from_str(lines[0]).expect("one JSON object");
    assert!(report["audit"]["score"].is_u64(), "{report}");
    assert_eq!(report["user_agent"], "probe-test/1");
}

#[test]
fn no_connection_is_exit_3_with_fail_under_and_exit_0_without() {
    let output = probe(&["--fail-under", "1"], None);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.contains("mirrust probe: no connection reached the probe server\n"),
        "{stderr}"
    );
    assert!(
        stderr.contains("--fail-under 1 needs a connection"),
        "{stderr}"
    );

    let output = probe(&[], None);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("no connection reached the probe server"),
        "{stderr}"
    );
}

#[test]
fn the_commands_failure_is_passed_through() {
    let output = probe(&["--fail-under", "1"], Some("fail"));
    assert_eq!(output.status.code(), Some(7), "{}", text(&output.stderr));
}

#[test]
fn a_command_that_cannot_run_is_exit_2() {
    let output = mirrust(&["probe", "--", "mirrust-no-such-command-x"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("cannot run mirrust-no-such-command-x"),
        "{stderr}"
    );
}

#[test]
fn usage_errors_are_exit_2_and_help_is_exit_0() {
    for args in [
        &["probe"][..],
        &["probe", "--fail-under", "101", "--", "x"],
        &["probe", "--listen", "127.0.0.1:1", "--", "x"],
        &["probe", "curl"],
    ] {
        let output = mirrust(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(text(&output.stderr).contains("mirrust probe"), "{args:?}");
    }
    let output = mirrust(&["probe", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout).contains("usage: mirrust probe"));
    let usage = text(&mirrust(&["--help"]).stdout);
    assert!(usage.contains("mirrust probe [--fail-under N]"), "{usage}");
}
