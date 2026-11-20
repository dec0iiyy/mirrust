//! `--log`: the binary appends one JSON line per request, HTTP/1.1 and HTTP/2 alike, and one per
//! TLS handshake that fails after the ClientHello; SIGTERM flushes the file.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fingerprint::{ClientHello, Ja3, Ja4, Transport};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::Value;
use server::self_signed_cert;
use tokio_rustls::TlsConnector;

/// Keys every entry has, in order.
const KEYS: [&str; 11] = [
    "time",
    "ip",
    "http_version",
    "method",
    "path",
    "user_agent",
    "ja3_hash",
    "ja4",
    "ja4_r",
    "ja4_peet",
    "peetprint_hash",
];

/// The server process, killed when the test ends however it ends, and what a test needs to
/// talk to it.
struct Server {
    child: Child,
    addr: SocketAddr,
    roots: RootCertStore,
    dir: PathBuf,
    log_path: PathBuf,
}

impl Server {
    /// Starts the binary with `--log` on an ephemeral port; `name` keeps tests apart on disk.
    fn start(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("request-log-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create the temp dir");
        let (certs, key) = self_signed_cert().expect("self-signed cert");
        let mut roots = RootCertStore::empty();
        roots.add(certs[0].clone()).expect("cert is a usable root");
        let (cert_path, key_path) = write_pem(&dir, &certs[0], &key);
        let log_path = dir.join("requests.jsonl");

        let mut child = Command::new(env!("CARGO_BIN_EXE_mirrust"))
            .args(["--listen", "127.0.0.1:0", "--cert"])
            .arg(&cert_path)
            .arg("--key")
            .arg(&key_path)
            .arg("--log")
            .arg(&log_path)
            .stdout(Stdio::piped())
            .spawn()
            .expect("start mirrust");
        let stdout = child.stdout.take().expect("piped stdout");
        let mut first_line = String::new();
        let mut stdout = BufReader::new(stdout);
        stdout.read_line(&mut first_line).expect("read stdout");
        let addr: SocketAddr = first_line
            .trim()
            .strip_prefix("listening on https://")
            .and_then(|rest| rest.split_whitespace().next())
            .expect("listening line")
            .parse()
            .expect("listening address");
        // The server prints a line per request; keep the pipe drained.
        std::thread::spawn(move || std::io::copy(&mut stdout, &mut std::io::sink()));
        Self {
            child,
            addr,
            roots,
            dir,
            log_path,
        }
    }

    /// Waits for the process to exit by itself.
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().expect("wait for mirrust") {
                return status;
            }
            assert!(Instant::now() < deadline, "mirrust did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn log_gets_one_json_line_per_request() {
    let server = Server::start("requests");
    let (addr, roots, log_path) = (server.addr, server.roots.clone(), &server.log_path);

    get_http1(addr, roots.clone(), "/api/clean");
    get_h2(addr, roots, "/api/all?x=1");

    let lines = wait_for_lines(log_path, 2);
    let entries: Vec<Value> = lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("each line is JSON"))
        .collect();

    let h1 = &entries[0];
    assert_eq!(keys(h1), KEYS, "{h1}");
    assert_eq!(h1["http_version"], "HTTP/1.1");
    assert_eq!(h1["method"], "GET");
    assert_eq!(h1["path"], "/api/clean");
    assert_eq!(h1["user_agent"], "it/1");

    let h2 = &entries[1];
    let mut h2_keys = KEYS.to_vec();
    h2_keys.extend(["akamai_fingerprint", "akamai_fingerprint_hash"]);
    assert_eq!(keys(h2), h2_keys, "{h2}");
    assert_eq!(h2["http_version"], "h2");
    assert_eq!(h2["path"], "/api/all?x=1");
    assert_ne!(h2["akamai_fingerprint"], "", "{h2}");

    for entry in &entries {
        let time = entry["time"].as_str().expect("time is a string");
        assert!(
            time.len() == 24 && time.ends_with('Z') && time.as_bytes()[10] == b'T',
            "RFC 3339 UTC time: {time}"
        );
        assert!(
            entry["ip"]
                .as_str()
                .is_some_and(|ip| ip.starts_with("127.0.0.1:")),
            "{entry}"
        );
        assert_eq!(
            entry["ja3_hash"].as_str().map(str::len),
            Some(32),
            "{entry}"
        );
    }
}

/// A scanner's connection: a real ClientHello, then nothing. The handshake cannot finish, and
/// the log still gets the fingerprints, with the request fields empty.
#[test]
fn failed_handshake_is_logged_with_its_fingerprints() {
    let server = Server::start("failed-handshake");
    let message = corpus_hello();
    let length = u16::try_from(message.len()).expect("the hello fits one record");

    let mut socket = TcpStream::connect(server.addr).expect("connect");
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(&message);
    socket.write_all(&record).expect("send the ClientHello");
    socket.shutdown(std::net::Shutdown::Write).expect("hang up");
    // Whatever the server sent before it noticed is of no interest.
    let _ = socket.read_to_end(&mut Vec::new());

    let lines = wait_for_lines(&server.log_path, 1);
    let entry: Value = serde_json::from_str(&lines[0]).expect("the line is JSON");
    let mut want_keys = KEYS.to_vec();
    want_keys.push("handshake_error");
    assert_eq!(keys(&entry), want_keys, "{entry}");
    for key in ["http_version", "method", "path", "user_agent"] {
        assert_eq!(entry[key], "", "{key} in {entry}");
    }
    assert!(
        entry["ip"]
            .as_str()
            .is_some_and(|ip| ip.starts_with("127.0.0.1:")),
        "{entry}"
    );
    let ja3 = Ja3::new(&ClientHello::parse_peet(&message));
    let ja4 = Ja4::new(&ClientHello::parse(&message), Transport::Tcp);
    assert_eq!(entry["ja3_hash"], ja3.hash(), "{entry}");
    assert_eq!(entry["ja4"], ja4.hashed(), "{entry}");
    assert_eq!(entry["ja4_r"], ja4.raw(), "{entry}");
    assert!(
        entry["ja4_peet"]
            .as_str()
            .is_some_and(|ja4_peet| ja4_peet.starts_with("t0")),
        "no version was negotiated: {entry}"
    );
    assert!(
        entry["handshake_error"]
            .as_str()
            .is_some_and(|error| !error.is_empty()),
        "{entry}"
    );
}

/// `systemd` stops a service with SIGTERM: the log must be flushed and the exit status 0.
#[cfg(unix)]
#[test]
fn sigterm_flushes_the_log_and_exits_with_status_zero() {
    let mut server = Server::start("sigterm");
    get_http1(server.addr, server.roots.clone(), "/api/clean");

    let killed = Command::new("kill")
        .args(["-TERM", &server.child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(killed.success(), "kill -TERM: {killed}");
    let status = server.wait();
    assert_eq!(status.code(), Some(0), "{status}");

    let text = fs::read_to_string(&server.log_path).expect("read the log");
    assert_eq!(text.lines().count(), 1, "{text:?}");
    assert!(text.ends_with('\n'), "{text:?}");
}

/// The first ClientHello of the corpus, as a handshake message.
fn corpus_hello() -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../corpus/hellos.jsonl");
    let corpus = fs::read_to_string(path).expect("read corpus/hellos.jsonl");
    let first: Value =
        serde_json::from_str(corpus.lines().next().expect("a first line")).expect("JSON line");
    let hex = first["hex"].as_str().expect("hex field");
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(pair, 16).expect("hex digits")
        })
        .collect()
}

fn keys(entry: &Value) -> Vec<&str> {
    entry
        .as_object()
        .expect("each line is an object")
        .keys()
        .map(String::as_str)
        .collect()
}

/// The log is flushed about once a second; waits for `count` complete lines.
fn wait_for_lines(path: &Path, count: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if lines.len() >= count && text.ends_with('\n') {
            assert_eq!(lines.len(), count, "{text}");
            return lines;
        }
        assert!(Instant::now() < deadline, "log has {text:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn get_http1(addr: SocketAddr, roots: RootCertStore, path: &str) {
    let config = client_config(roots, b"http/1.1");
    let name = ServerName::try_from("localhost").expect("valid name");
    let conn = ClientConnection::new(Arc::new(config), name).expect("client connection");
    let socket = TcpStream::connect(addr).expect("connect");
    let mut tls = StreamOwned::new(conn, socket);
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: it/1\r\n\r\n");
    tls.write_all(request.as_bytes()).expect("send request");
    let mut response = Vec::new();
    // The server closes after one response; a missing close_notify is not this test's concern.
    let _ = tls.read_to_end(&mut response);
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
}

fn get_h2(addr: SocketAddr, roots: RootCertStore, path: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let connector = TlsConnector::from(Arc::new(client_config(roots, b"h2")));
        let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let name = ServerName::try_from("localhost").expect("valid name");
        let tls = connector
            .connect(name, socket)
            .await
            .expect("TLS handshake");
        let (mut sender, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
        tokio::spawn(connection);
        let request = http::Request::get(format!("https://localhost{path}"))
            .body(())
            .expect("valid request");
        let (response, _) = sender.send_request(request, true).expect("send");
        let response = response.await.expect("response");
        assert_eq!(response.status(), 200);
        let headers = response.headers();
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["referrer-policy"], "no-referrer");
    });
}

fn client_config(roots: RootCertStore, alpn: &[u8]) -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

/// Writes the certificate and key as PEM files, which is what `--cert` and `--key` read.
fn write_pem(dir: &Path, cert: &CertificateDer<'_>, key: &PrivateKeyDer<'_>) -> (PathBuf, PathBuf) {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    fs::write(&cert_path, pem("CERTIFICATE", cert)).expect("write cert.pem");
    fs::write(&key_path, pem("PRIVATE KEY", key.secret_der())).expect("write key.pem");
    (cert_path, key_path)
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = base64(der);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect();
    let body = lines.join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

/// Standard padded base64.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}
