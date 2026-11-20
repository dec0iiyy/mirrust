//! Property tests: `Syn::parse` takes any bytes, and what it returns is well-formed.
//!
//! Inputs are arbitrary bytes, packets built from random header fields (so the option readers
//! run instead of the header checks rejecting nearly every case), and the packets of
//! `corpus/syn.jsonl` with bytes flipped, cut off and inserted.

use proptest::prelude::*;
use proptest::sample::Index;
use serde_json::Value;
use tcpip::{Syn, TcpIp};

const PACKETS: &str = include_str!("../../../corpus/syn.jsonl");

/// p0f reads at most this many TCP options.
const MAX_OPTIONS: usize = 24;
/// A TCP header holds at most 40 option bytes (data offset 15).
const MAX_OPTION_BYTES: usize = 40;

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("corpus hex is valid"))
        .collect()
}

fn corpus() -> Vec<Vec<u8>> {
    PACKETS
        .lines()
        .map(|line| {
            let input: Value = serde_json::from_str(line).expect("corpus line is JSON");
            decode_hex(input["hex"].as_str().expect("corpus hex"))
        })
        .collect()
}

/// One edit of a packet.
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

/// A real packet from the corpus after one to four edits.
fn mutated_packet() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::sample::select(corpus()),
        prop::collection::vec(mutation(), 1..=4),
    )
        .prop_map(|(mut packet, mutations)| {
            for mutation in &mutations {
                apply(&mut packet, mutation);
            }
            packet
        })
}

/// TCP option bytes that mostly start with a kind the parser knows.
fn tcp_options() -> impl Strategy<Value = Vec<u8>> {
    let byte = prop_oneof![0..=8_u8, any::<u8>()];
    prop::collection::vec(byte, 0..=MAX_OPTION_BYTES)
}

/// A TCP segment with a random data offset, flags (usually a bare SYN), options and payload.
fn tcp_segment() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::array::uniform20(any::<u8>()),
        prop_oneof![Just(None), (0..=15_u8).prop_map(Some)],
        prop_oneof![4 => Just(0x02_u8), 1 => any::<u8>()],
        tcp_options(),
        prop::collection::vec(any::<u8>(), 0..16),
    )
        .prop_map(|(mut header, offset, flags, options, payload)| {
            // Without an explicit offset, the one that covers exactly the options.
            let words = offset.unwrap_or_else(|| {
                u8::try_from(5 + options.len().div_ceil(4)).expect("at most 15 words")
            });
            header[12] = words << 4 | (header[12] & 0x01);
            header[13] = flags;
            let mut segment = header.to_vec();
            segment.extend(options);
            segment.extend(payload);
            segment
        })
}

/// An IPv4 or IPv6 packet around a [`tcp_segment`], with lengths that are usually right.
fn ip_packet() -> impl Strategy<Value = Vec<u8>> {
    let v4 = (
        tcp_segment(),
        prop::array::uniform20(any::<u8>()),
        prop_oneof![1..=8_u8, any::<u8>()].prop_flat_map(|kind| {
            prop::collection::vec(prop_oneof![Just(kind), any::<u8>()], 0..=40)
        }),
        prop_oneof![3 => Just(None), 1 => any::<u16>().prop_map(Some)],
        prop_oneof![4 => Just(0_u16), 1 => any::<u16>()],
        prop_oneof![4 => Just(6_u8), 1 => any::<u8>()],
    )
        .prop_map(
            |(segment, mut header, mut options, length, fragment, protocol)| {
                options.truncate(options.len() / 4 * 4);
                let words = u8::try_from(5 + options.len() / 4).expect("at most 15 words");
                header[0] = 0x40 | words;
                let total = 20 + options.len() + segment.len();
                let total = length.unwrap_or_else(|| u16::try_from(total).expect("short packet"));
                header[2..4].copy_from_slice(&total.to_be_bytes());
                header[6..8].copy_from_slice(&fragment.to_be_bytes());
                header[9] = protocol;
                let mut packet = header.to_vec();
                packet.extend(options);
                packet.extend(segment);
                packet
            },
        );
    let v6 = (
        tcp_segment(),
        prop::collection::vec(any::<u8>(), 40),
        prop_oneof![3 => Just(None), 1 => any::<u16>().prop_map(Some)],
        prop_oneof![4 => Just(6_u8), 1 => any::<u8>()],
    )
        .prop_map(|(segment, mut header, length, next_header)| {
            header[0] = 0x60 | (header[0] & 0x0f);
            let payload = u16::try_from(segment.len()).expect("short segment");
            header[4..6].copy_from_slice(&length.unwrap_or(payload).to_be_bytes());
            header[6] = next_header;
            header.extend(segment);
            header
        });
    prop_oneof![v4, v6]
}

/// Parses `packet` and checks what comes back; returns whether it was a SYN.
fn exercise(packet: &[u8]) -> Result<bool, TestCaseError> {
    let Some(syn) = Syn::parse(packet) else {
        prop_assert_eq!(
            serde_json::to_string(&TcpIp::new(None)).ok(),
            Some(r#"{"ip":{},"tcp":{}}"#.to_owned())
        );
        return Ok(false);
    };
    let details = &syn.details;
    prop_assert!(matches!(details.ip_version, 4 | 6));
    prop_assert!(details.options.len() <= MAX_OPTIONS);
    prop_assert!(details.options_raw.len() <= 2 * MAX_OPTION_BYTES);
    prop_assert!(details.payload_len <= packet.len());
    prop_assert_eq!(&details.option_order, &details.options.join(","));
    prop_assert_eq!(details.ip_id.is_some(), details.ip_version == 4);
    // ver:ttl:olen:mss:wsize,scale:olayout:quirks:pclass
    prop_assert_eq!(syn.p0f.split(':').count(), 8, "p0f {}", &syn.p0f);

    let json = serde_json::to_value(TcpIp::new(Some(syn.clone())));
    prop_assert!(json.is_ok_and(|json| json["tcp_syn"].is_object() && json["p0f"] == syn.p0f));
    Ok(true)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn arbitrary_bytes_parse(packet in prop::collection::vec(any::<u8>(), 0..256)) {
        exercise(&packet)?;
    }

    #[test]
    fn built_packets_parse(packet in ip_packet()) {
        exercise(&packet)?;
    }

    #[test]
    fn mutated_real_packets_parse(packet in mutated_packet()) {
        exercise(&packet)?;
    }
}

/// The builder above must reach the option readers, or the properties check nothing.
#[test]
fn built_packets_are_often_syns() {
    use proptest::strategy::ValueTree as _;
    use proptest::test_runner::TestRunner;

    let mut runner = TestRunner::deterministic();
    let strategy = ip_packet();
    let syns = (0..256)
        .filter(|_| {
            let packet = strategy
                .new_tree(&mut runner)
                .expect("the strategy rejects nothing")
                .current();
            Syn::parse(&packet).is_some()
        })
        .count();
    assert!(syns >= 32, "only {syns} of 256 built packets were SYNs");
}
