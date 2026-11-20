//! Property tests: `ClientHello::parse` and `parse_peet` take any bytes, and every fingerprint
//! and detail computed from the result is well-formed and no larger than the input allows.
//!
//! Inputs are arbitrary bytes, bytes behind a ClientHello header, and the real hellos of
//! `corpus/hellos.jsonl` with bytes flipped, cut off and inserted.

mod common;

use fingerprint::{ClientHello, Ja4, Transport};
use proptest::prelude::*;
use proptest::sample::Index;

use common::{cases, snapshot_line};

const HELLOS: &str = include_str!("../../../corpus/hellos.jsonl");

/// Characters of output one input byte can turn into. The widest case is a two-byte cipher
/// suite: its registry name, plus its decimal and hex forms in JA3, JA4 and PeetPrint.
const MAX_GROWTH: usize = 64;
/// Keys, hashes and separators of one snapshot line, whatever the input.
const FIXED_OUTPUT: usize = 2048;

/// One edit of a message.
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

/// A real hello from the corpus after one to four edits.
fn mutated_hello() -> impl Strategy<Value = Vec<u8>> {
    let hellos: Vec<Vec<u8>> = cases(HELLOS).map(|(_, message)| message).collect();
    (
        prop::sample::select(hellos),
        prop::collection::vec(mutation(), 1..=4),
    )
        .prop_map(|(mut message, mutations)| {
            for mutation in &mutations {
                apply(&mut message, mutation);
            }
            message
        })
}

/// Random bytes behind a ClientHello header with a version `parse_peet` reads past, so the
/// body parsers see them instead of the header check rejecting nearly every case.
fn hello_shaped() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::sample::select(vec![0x0301_u16, 0x0303, 0x0304]),
        prop::collection::vec(any::<u8>(), 0..1024),
    )
        .prop_map(|(version, body)| {
            let mut message = vec![1, 0, 0, 0];
            message.extend(version.to_be_bytes());
            message.extend(body);
            message
        })
}

/// An extension block of well-formed type-length-value entries with random contents, behind
/// a minimal hello, so every extension reader runs on data of every length.
fn random_extensions() -> impl Strategy<Value = Vec<u8>> {
    let kind = prop_oneof![
        prop::sample::select(vec![
            0x0000_u16, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0011, 0x0012, 0x0015, 0x0017,
            0x001b, 0x0022, 0x002b, 0x002d, 0x0033, 0x0035, 0x4469, 0x44cd, 0x0a0a,
        ]),
        any::<u16>(),
    ];
    let extension = (kind, prop::collection::vec(any::<u8>(), 0..48));
    prop::collection::vec(extension, 0..24).prop_map(|extensions| {
        let mut block = Vec::new();
        for (kind, data) in extensions {
            block.extend(kind.to_be_bytes());
            block.extend(u16::try_from(data.len()).expect("short data").to_be_bytes());
            block.extend(data);
        }
        let mut message = vec![1, 0, 0, 0, 3, 3];
        message.extend([0; 32]); // random
        message.push(0); // session id
        message.extend([0, 2, 0x13, 0x01]); // one cipher suite
        message.extend([1, 0]); // null compression
        message.extend(
            u16::try_from(block.len())
                .expect("short block")
                .to_be_bytes(),
        );
        message.extend(block);
        message
    })
}

/// Parses `message` both ways and computes everything the crate offers from each result.
fn exercise(message: &[u8]) -> Result<(), TestCaseError> {
    for hello in [
        ClientHello::parse(message),
        ClientHello::parse_peet(message),
    ] {
        // Every parsed field is a copy of part of the message.
        let extension_bytes: usize = hello.extensions.iter().map(|e| 4 + e.data.len()).sum();
        prop_assert!(extension_bytes <= message.len());
        prop_assert!(2 * hello.cipher_suites.len() <= message.len());
        prop_assert!(u8::try_from(hello.session_id.len()).is_ok());
        prop_assert!(hello.random.is_empty() || hello.random.len() == 32);

        for transport in [Transport::Tcp, Transport::Quic, Transport::Dtls] {
            let ja4 = Ja4::new(&hello, transport);
            // Ten characters of part a, then two 12-digit hashes.
            for hashed in [ja4.hashed(), ja4.original()] {
                prop_assert_eq!(hashed.len(), 36, "JA4 {}", hashed);
                prop_assert!(hashed.is_ascii(), "JA4 {}", hashed);
            }
            for raw in [ja4.raw(), ja4.raw_original()] {
                prop_assert!(raw.len() <= MAX_GROWTH * message.len() + FIXED_OUTPUT);
            }
        }

        // JA3, tls.peet.ws's JA4, PeetPrint, readable ciphers and extension details, as JSON.
        let line = snapshot_line("case", &hello);
        prop_assert!(
            line.len() <= MAX_GROWTH * message.len() + FIXED_OUTPUT,
            "{} bytes of input gave {} bytes of output",
            message.len(),
            line.len()
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_parse(message in prop::collection::vec(any::<u8>(), 0..2048)) {
        exercise(&message)?;
    }

    #[test]
    fn hello_shaped_bytes_parse(message in hello_shaped()) {
        exercise(&message)?;
    }

    #[test]
    fn random_extensions_parse(message in random_extensions()) {
        exercise(&message)?;
    }

    #[test]
    fn mutated_real_hellos_parse(message in mutated_hello()) {
        exercise(&message)?;
    }
}
