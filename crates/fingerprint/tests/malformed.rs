//! Truncated and malformed `ClientHello`s from `corpus/malformed.jsonl`: parsing and every
//! fingerprint never panic, and what tls.peet.ws would report matches the snapshot in
//! `corpus/malformed_expected.jsonl`.
//!
//! Run with `MIRRUST_BLESS=1` to accept a deliberate change; see the `golden` crate.

mod common;

use fingerprint::{ClientHello, Ja4, Transport};

use common::{cases, snapshot_line};

const CASES: &str = include_str!("../../../corpus/malformed.jsonl");

#[test]
fn malformed_hellos_never_panic_and_match_snapshot() {
    let lines: Vec<String> = cases(CASES)
        .map(|(name, message)| {
            // The spec JA4 is not in the snapshot, but computing it must not panic either.
            let _ = Ja4::new(&ClientHello::parse(&message), Transport::Tcp);
            snapshot_line(&name, &ClientHello::parse_peet(&message))
        })
        .collect();
    assert!(lines.len() > 300, "corpus too small: {}", lines.len());
    golden::check("malformed_expected.jsonl", &lines);
}
