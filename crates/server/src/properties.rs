//! Property tests for the two parsers of this crate that read straight off a connection: the
//! ClientHello capture and the HTTP/1 request reader. Both take any `AsyncRead`, so they run
//! here on in-memory streams, without a socket or a TLS handshake.

use std::net::SocketAddr;

use fingerprint::Transport;
use proptest::prelude::*;
use proptest::sample::Index;
use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::runtime::{Builder, Runtime};

use crate::capture::{MAX_HELLO_BYTES, read_client_hello};
use crate::report::TlsDetails;
use crate::{Config, http1};

const HELLOS: &str = include_str!("../../../corpus/hellos.jsonl");

/// `read_client_hello` reads the stream in chunks of this size, so it may hold this much
/// past the record it needed.
const READ_CHUNK: usize = 4096;

fn runtime() -> Runtime {
    Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime starts")
}

fn hellos() -> Vec<Vec<u8>> {
    HELLOS
        .lines()
        .map(|line| {
            let input: Value = serde_json::from_str(line).expect("corpus line is JSON");
            let hex = input["hex"].as_str().expect("corpus hex");
            (0..hex.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("corpus hex is valid"))
                .collect()
        })
        .collect()
}

/// One edit of a byte string.
#[derive(Debug, Clone)]
enum Mutation {
    /// XOR the byte at this position with a non-zero mask.
    Flip(Index, u8),
    /// Keep only the bytes before this position.
    Truncate(Index),
    /// Put these bytes in at this position.
    Insert(Index, Vec<u8>),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<Index>(), 1..=u8::MAX).prop_map(|(at, mask)| Mutation::Flip(at, mask)),
        any::<Index>().prop_map(Mutation::Truncate),
        (any::<Index>(), prop::collection::vec(any::<u8>(), 1..16))
            .prop_map(|(at, bytes)| Mutation::Insert(at, bytes)),
    ]
}

fn apply(bytes: &mut Vec<u8>, mutation: &Mutation) {
    match mutation {
        Mutation::Flip(at, mask) => {
            if !bytes.is_empty() {
                let at = at.index(bytes.len());
                bytes[at] ^= mask;
            }
        }
        Mutation::Truncate(at) => bytes.truncate(at.index(bytes.len() + 1)),
        Mutation::Insert(at, extra) => {
            let at = at.index(bytes.len() + 1);
            bytes.splice(at..at, extra.iter().copied());
        }
    }
}

/// A real hello cut into one to four handshake records (some of them empty), with bytes
/// after it, then edited zero to three times.
fn hello_records() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::sample::select(hellos()),
        prop::collection::vec(any::<Index>(), 0..=3),
        prop::collection::vec(any::<u8>(), 0..32),
        prop::collection::vec(mutation(), 0..=3),
    )
        .prop_map(|(hello, cuts, trailer, mutations)| {
            let mut cuts: Vec<usize> = cuts.iter().map(|cut| cut.index(hello.len() + 1)).collect();
            cuts.extend([0, hello.len()]);
            cuts.sort_unstable();
            let mut wire = Vec::new();
            for bounds in cuts.windows(2) {
                let body = &hello[bounds[0]..bounds[1]];
                wire.extend([22, 3, 1]);
                wire.extend(
                    u16::try_from(body.len())
                        .expect("short record")
                        .to_be_bytes(),
                );
                wire.extend(body);
            }
            wire.extend(trailer);
            for mutation in &mutations {
                apply(&mut wire, mutation);
            }
            wire
        })
}

/// Runs the capture on `wire` and checks what it returns; gives the captured message.
fn capture(runtime: &Runtime, wire: &[u8]) -> Result<Option<Vec<u8>>, TestCaseError> {
    let mut stream = wire;
    let Ok((raw, message)) = runtime.block_on(read_client_hello(&mut stream)) else {
        return Ok(None);
    };
    // Everything read is kept for the replay, in order, and reading stops near the limit.
    prop_assert_eq!(&raw[..], &wire[..raw.len()]);
    prop_assert_eq!(stream, &wire[raw.len()..]);
    prop_assert!(raw.len() <= MAX_HELLO_BYTES + READ_CHUNK);
    prop_assert!(message.len() >= 4 && message.len() <= MAX_HELLO_BYTES);
    prop_assert_eq!(message[0], 1);
    let declared =
        usize::from(message[1]) << 16 | usize::from(message[2]) << 8 | usize::from(message[3]);
    prop_assert_eq!(message.len(), 4 + declared);
    Ok(Some(message))
}

/// A request line and headers that are usually well-formed, for one of the routes or not.
fn request() -> impl Strategy<Value = Vec<u8>> {
    let token = || "[A-Za-z0-9:/%?#=&._ -]{0,24}";
    let path = prop_oneof![
        prop::sample::select(vec![
            "/",
            "/api/all",
            "/api/tls",
            "/api/clean",
            "/api/raw",
            "/api/%61ll?x=1",
            "/%zz",
            "*",
        ])
        .prop_map(str::to_owned),
        token().prop_map(|rest| format!("/{rest}")),
        token(),
    ];
    let method = prop_oneof![
        prop::sample::select(vec!["GET", "POST", "OPTIONS", "HEAD"]).prop_map(str::to_owned),
        token(),
    ];
    let header = prop_oneof![
        token().prop_map(|value| format!("User-Agent: {value}")),
        token().prop_map(|value| format!("x-cors{value}: 1")),
        (token(), token()).prop_map(|(name, value)| format!("{name}: {value}")),
        token(),
    ];
    let line_end = || prop_oneof![4 => Just("\r\n"), 1 => Just("\n"), 1 => Just("")];
    (
        method,
        path,
        prop_oneof![4 => Just("HTTP/1.1".to_owned()), 1 => token()],
        prop::collection::vec((header, line_end()), 0..12),
        line_end(),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(method, path, version, headers, end, body)| {
            let mut text = format!("{method} {path} {version}\r\n");
            for (header, line_end) in headers {
                text.push_str(&header);
                text.push_str(line_end);
            }
            text.push_str(end);
            let mut bytes = text.into_bytes();
            bytes.extend(body);
            bytes
        })
}

/// Sends `request` to `http1::serve` over an in-memory stream and checks the response.
fn serve(runtime: &Runtime, request: &[u8], tls: TlsDetails) -> Result<(), TestCaseError> {
    let peer: SocketAddr = ([192, 0, 2, 1], 4433).into();
    let config = Config::default();
    let (mut client, server) = tokio::io::duplex(4096);
    let (outcome, response) = runtime.block_on(async {
        // Requests here fit the stream's buffer, so this does not wait for the server.
        client.write_all(request).await.expect("the request fits");
        client.shutdown().await.expect("in-memory shutdown");
        let mut response = Vec::new();
        let (outcome, read) = tokio::join!(
            http1::serve(server, peer, tls, &config),
            client.read_to_end(&mut response),
        );
        read.expect("in-memory read");
        (outcome, response)
    });
    if request.is_empty() {
        prop_assert!(outcome.is_err(), "no request, no response");
        return Ok(());
    }
    prop_assert!(outcome.is_ok(), "serving failed: {:?}", outcome);

    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| TestCaseError::fail("the response has no header block"))?;
    let head = std::str::from_utf8(&response[..head_end])
        .map_err(|_| TestCaseError::fail("the response head is not UTF-8"))?;
    let body = &response[head_end + 4..];
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    prop_assert!(
        matches!(
            status,
            "HTTP/1.1 200 OK" | "HTTP/1.1 404 Not Found" | "HTTP/1.1 500 Internal Server Error"
        ),
        "status line {:?}",
        status
    );
    let length = lines
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .and_then(|value| value.parse::<usize>().ok());
    // A HEAD request gets no content; a malformed request line that starts with HEAD is not one.
    if request.starts_with(b"HEAD ") && body.is_empty() {
        prop_assert!(length.is_some(), "HEAD keeps Content-Length");
    } else {
        // Two CRLFs follow the body, past Content-Length.
        prop_assert_eq!(length.map(|length| length + 4), Some(body.len()));
    }
    // Nothing the client sent reaches the response head.
    prop_assert!(head.len() < 512, "response head of {} bytes", head.len());
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn capture_takes_arbitrary_bytes(wire in prop::collection::vec(any::<u8>(), 0..2048)) {
        capture(&runtime(), &wire)?;
    }

    #[test]
    fn capture_takes_arbitrary_handshake_records(
        records in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 0..12),
    ) {
        let wire: Vec<u8> = records
            .iter()
            .flat_map(|body| {
                let len = u16::try_from(body.len()).expect("short record").to_be_bytes();
                [22, 3, 1].into_iter().chain(len).chain(body.iter().copied())
            })
            .collect();
        capture(&runtime(), &wire)?;
    }

    #[test]
    fn captured_hellos_fingerprint_and_serve(
        wire in hello_records(),
        request in request(),
    ) {
        let runtime = runtime();
        if let Some(message) = capture(&runtime, &wire)? {
            let tls = TlsDetails::new(&message, 0x0304, Transport::Tcp);
            serve(&runtime, &request, tls)?;
        }
    }

    #[test]
    fn http1_takes_arbitrary_bytes(request in prop::collection::vec(any::<u8>(), 0..2048)) {
        serve(&runtime(), &request, TlsDetails::default())?;
    }

    #[test]
    fn http1_takes_request_shaped_text(request in request()) {
        serve(&runtime(), &request, TlsDetails::default())?;
    }
}
