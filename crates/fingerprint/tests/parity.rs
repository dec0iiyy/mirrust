//! Every ClientHello of `corpus/hellos.jsonl` against its snapshot in `corpus/expected.jsonl`:
//! JA3, tls.peet.ws's JA4 and PeetPrint, readable ciphers and extension details.
//!
//! Run with `MIRRUST_BLESS=1` to accept a deliberate change; see the `golden` crate.

mod common;

use fingerprint::ClientHello;

use common::{cases, snapshot_line};

const HELLOS: &str = include_str!("../../../corpus/hellos.jsonl");

#[test]
fn fingerprints_match_snapshot() {
    let lines: Vec<String> = cases(HELLOS)
        .map(|(name, message)| snapshot_line(&name, &ClientHello::parse_peet(&message)))
        .collect();
    assert!(lines.len() > 100, "corpus too small: {}", lines.len());
    golden::check("expected.jsonl", &lines);
}
