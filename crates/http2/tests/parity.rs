//! Snapshot test: every connection of `corpus/h2.jsonl` through the parser, fed whole and in
//! small pieces, against `corpus/h2_expected.jsonl`: the outcome, the response stream, the
//! frame list and the Akamai fingerprint.
//!
//! Run with `MIRRUST_BLESS=1` to accept a deliberate change; see the `golden` crate.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http2::{Error, Parser, Status, akamai_fingerprint, akamai_fingerprint_hash};
use serde_json::{Value, json};

fn corpus(name: &str) -> Vec<Value> {
    golden::read_corpus(name)
        .lines()
        .map(|line| serde_json::from_str(line).expect("corpus lines are JSON"))
        .collect()
}

fn decode(input: &Value) -> Vec<u8> {
    STANDARD
        .decode(input["b64"].as_str().expect("b64"))
        .expect("valid base64")
}

/// Runs the parser the way `serve` does and names the outcome.
fn run(bytes: &[u8], piece: usize) -> (&'static str, Parser) {
    let mut parser = Parser::new();
    for chunk in bytes.chunks(piece.max(1)) {
        match parser.feed(chunk) {
            Ok(Status::Complete) => return ("respond", parser),
            Ok(Status::Incomplete) => {}
            Err(Error::BadPreface) => return ("not_h2", parser),
            Err(Error::HeaderDecode) => return ("hang", parser),
            Err(err) => panic!("unexpected error {err}"),
        }
    }
    // End of input: the server closes the connection. Frame errors close too.
    ("close", parser)
}

fn run_with_errors(bytes: &[u8], piece: usize) -> (&'static str, Parser) {
    let mut parser = Parser::new();
    for chunk in bytes.chunks(piece.max(1)) {
        match parser.feed(chunk) {
            Ok(Status::Complete) => return ("respond", parser),
            Ok(Status::Incomplete) => {}
            Err(Error::BadPreface) => return ("not_h2", parser),
            Err(Error::HeaderDecode) => return ("hang", parser),
            Err(_) => return ("close", parser),
        }
    }
    ("close", parser)
}

/// One snapshot line. A connection that is not HTTP/2 has no fingerprint, and an empty frame
/// list is `null`, as tls.peet.ws writes it.
fn snapshot_line(name: &str, outcome: &str, parser: &Parser) -> String {
    let frames = parser.frames();
    let (fingerprint, hash) = if outcome == "not_h2" {
        (String::new(), String::new())
    } else {
        (akamai_fingerprint(frames), akamai_fingerprint_hash(frames))
    };
    let frames = if frames.is_empty() {
        Value::Null
    } else {
        serde_json::to_value(frames).expect("frames serialize")
    };
    golden::json_line(&json!({
        "name": name,
        "outcome": outcome,
        "stream_id": parser.header_frame().map_or(0, |frame| frame.stream_id),
        "frames": frames,
        "akamai_fingerprint": fingerprint,
        "akamai_fingerprint_hash": hash,
    }))
}

#[test]
fn every_connection_matches_snapshot() {
    let inputs = corpus("h2.jsonl");
    assert_ne!(inputs.len(), 0, "empty corpus");

    let mut lines = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let name = input["name"].as_str().expect("name");
        let bytes = decode(input);
        let (outcome, parser) = run_with_errors(&bytes, bytes.len());
        let whole = snapshot_line(name, outcome, &parser);
        for piece in [1, 7, 100] {
            let (outcome, parser) = run_with_errors(&bytes, piece);
            assert_eq!(
                snapshot_line(name, outcome, &parser),
                whole,
                "{name}: fed in pieces of {piece}"
            );
        }
        lines.push(whole);
    }
    golden::check("h2_expected.jsonl", &lines);
}

#[test]
fn real_clients_never_hit_a_frame_error() {
    for input in corpus("h2.jsonl") {
        let name = input["name"].as_str().expect("name");
        if name.starts_with("synth-") {
            continue;
        }
        let bytes = decode(&input);
        let (outcome, _) = run(&bytes, bytes.len());
        assert_eq!(outcome, "respond", "{name}");
    }
}

#[test]
fn truncated_and_corrupted_input_never_panics() {
    for input in corpus("h2.jsonl") {
        let bytes = decode(&input);
        for end in 0..bytes.len() {
            let _ = run_with_errors(&bytes[..end], 13);
            let mut flipped = bytes.clone();
            flipped[end] ^= 0xa5;
            let _ = run_with_errors(&flipped, bytes.len());
        }
    }
}
