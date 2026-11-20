//! Every packet of `corpus/syn.jsonl` against its snapshot in `corpus/syn_expected.jsonl`:
//! whether it yields a SYN, the `tcp_syn` details and the p0f signature.
//!
//! Run with `MIRRUST_BLESS=1` to accept a deliberate change; see the `golden` crate.

use serde_json::{Value, json};
use tcpip::{Syn, TcpIp};

const PACKETS: &str = include_str!("../../../corpus/syn.jsonl");

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("corpus hex is valid"))
        .collect()
}

#[test]
fn syn_fingerprints_match_snapshot() {
    let lines: Vec<String> = PACKETS
        .lines()
        .map(|input| {
            let input: Value = serde_json::from_str(input).expect("corpus line is JSON");
            let name = input["name"].as_str().expect("corpus name");
            let syn = Syn::parse(&decode_hex(input["hex"].as_str().expect("corpus hex")));
            let (details, p0f) = syn.map_or((Value::Null, String::new()), |syn| {
                let details = serde_json::to_value(&syn.details).expect("details serialize");
                (details, syn.p0f)
            });
            golden::json_line(&json!({
                "name": name,
                "ok": !details.is_null(),
                "details": details,
                "p0f": p0f,
            }))
        })
        .collect();
    golden::check("syn_expected.jsonl", &lines);
}

#[test]
fn tcpip_object_has_peet_shape() {
    let empty = serde_json::to_string(&TcpIp::default()).expect("serialize");
    assert_eq!(empty, r#"{"ip":{},"tcp":{}}"#);

    let first = PACKETS.lines().next().expect("corpus is not empty");
    let input: Value = serde_json::from_str(first).expect("corpus line is JSON");
    let syn = Syn::parse(&decode_hex(input["hex"].as_str().expect("corpus hex")));
    let tcpip = TcpIp::new(syn);
    let json: Value = serde_json::to_value(&tcpip).expect("serialize");
    let keys: Vec<&str> = json
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["ip", "tcp", "tcp_syn", "p0f"]);
    assert_eq!(
        tcpip.p0f(),
        "4:47+?:0:1460:64240,8:mss,sok,ts,nop,ws:df,id+:0"
    );
}
