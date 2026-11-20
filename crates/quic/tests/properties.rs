//! Property tests: `InitialAssembler::push` takes any datagram, keeps no more than its limit,
//! and returns a ClientHello only when it has one.
//!
//! Inputs are arbitrary datagrams, random bytes behind a valid long header, the Initial
//! datagrams Chrome sent (`tests/data`) with bytes flipped, cut off and inserted, and, since
//! none of those survive decryption, Initial packets sealed here with the client's keys around
//! random frames, so the frame reader and the CRYPTO reassembly run on hostile input too.

use proptest::prelude::*;
use proptest::sample::Index;
use quic::{ClientInitial, Error, InitialAssembler, MAX_CRYPTO_LEN, Version};
use rustls::Side;

const CHROME_DATAGRAMS: &str = include_str!("data/chrome160_datagrams.hex");
const RFC_PACKET: &str = include_str!("data/rfc9001_a2_protected_packet.hex");

const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
const INITIAL_V1: u8 = 0;
const HANDSHAKE_V1: u8 = 2;

fn unhex(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn real_datagrams() -> Vec<Vec<u8>> {
    CHROME_DATAGRAMS
        .lines()
        .chain([RFC_PACKET])
        .map(unhex)
        .collect()
}

/// One edit of a datagram.
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

/// Chrome's two datagrams and the RFC 9001 packet, each as sent or after one to three edits.
/// Edits near the start hit the header fields; anywhere else they break the AEAD tag.
fn mutated_flight() -> impl Strategy<Value = Vec<Vec<u8>>> {
    let edits = prop::collection::vec(mutation(), 0..=3);
    prop::collection::vec(edits, 3).prop_map(|edits| {
        real_datagrams()
            .into_iter()
            .zip(edits)
            .map(|(mut datagram, edits)| {
                for edit in &edits {
                    apply(&mut datagram, edit);
                }
                datagram
            })
            .collect()
    })
}

/// A variable-length integer (RFC 9000 section 16) in its shortest form.
fn varint(out: &mut Vec<u8>, value: u64) {
    let value = value & ((1 << 62) - 1);
    if value < 1 << 6 {
        out.push(u8::try_from(value).expect("six bits"));
    } else if value < 1 << 14 {
        out.extend((0x4000 | u16::try_from(value).expect("14 bits")).to_be_bytes());
    } else if value < 1 << 30 {
        out.extend((0x8000_0000 | u32::try_from(value).expect("30 bits")).to_be_bytes());
    } else {
        out.extend((0xc000_0000_0000_0000 | value).to_be_bytes());
    }
}

/// Random bytes behind a long header that parses: a version, connection IDs and a token of
/// valid lengths, and a length field that is usually right.
fn long_header_datagram() -> impl Strategy<Value = Vec<u8>> {
    let version = prop_oneof![Just(1_u32), Just(0x6b33_43cf), any::<u32>()];
    let cid = || prop::collection::vec(any::<u8>(), 0..=20);
    (
        any::<u8>(),
        version,
        cid(),
        cid(),
        prop::collection::vec(any::<u8>(), 0..8),
        prop_oneof![3 => Just(None), 1 => any::<u64>().prop_map(Some)],
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(any::<u8>(), 0..8),
    )
        .prop_map(
            |(first, version, dcid, scid, token, length, body, trailer)| {
                let mut datagram = vec![0x80 | first];
                datagram.extend(version.to_be_bytes());
                for id in [&dcid, &scid] {
                    datagram.push(u8::try_from(id.len()).expect("short id"));
                    datagram.extend(id);
                }
                varint(&mut datagram, token.len() as u64);
                datagram.extend(token);
                varint(&mut datagram, length.unwrap_or(body.len() as u64));
                datagram.extend(body);
                datagram.extend(trailer);
                datagram
            },
        )
}

/// Builds a protected long-header packet (4-byte packet number, empty token) the way a client
/// would, around any plaintext.
fn seal(kind: u8, dcid: &[u8], pn: u32, frames: &[u8]) -> Vec<u8> {
    let keys = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(rustls::Tls13CipherSuite::quic_suite)
        .expect("QUIC suite")
        .keys(dcid, Side::Client, rustls::quic::Version::V1)
        .local;
    let mut header = vec![0xc3 | (kind << 4)];
    header.extend(Version::V1.to_wire().to_be_bytes());
    header.push(u8::try_from(dcid.len()).expect("short dcid"));
    header.extend(dcid);
    header.push(0); // no source connection ID
    if kind == INITIAL_V1 {
        header.push(0); // token length
    }
    let length = u16::try_from(4 + frames.len() + 16).expect("short packet");
    header.extend((0x4000 | length).to_be_bytes());
    let pn_offset = header.len();
    header.extend(pn.to_be_bytes());

    let mut payload = frames.to_vec();
    let tag = keys
        .packet
        .encrypt_in_place(u64::from(pn), &header, &mut payload)
        .expect("seal");
    payload.extend(tag.as_ref());
    let (first, pn_field) = header.split_at_mut(pn_offset);
    keys.header
        .encrypt_in_place(&payload[..16], &mut first[0], pn_field)
        .expect("protect header");
    header.extend(payload);
    header
}

fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x06];
    varint(&mut frame, offset);
    varint(&mut frame, data.len() as u64);
    frame.extend(data);
    frame
}

/// Any varint value, small ones and the limits of the CRYPTO stream more often.
fn offset() -> impl Strategy<Value = u64> {
    let limit = MAX_CRYPTO_LEN as u64;
    prop_oneof![
        4 => 0..512_u64,
        2 => limit - 64..limit + 64,
        1 => any::<u64>(),
        1 => Just((1 << 62) - 1),
    ]
}

/// One frame of an Initial packet's plaintext, allowed there or not, whole or not.
fn hostile_frame() -> impl Strategy<Value = Vec<u8>> {
    let count = || prop_oneof![0..4_u64, any::<u64>()];
    prop_oneof![
        4 => (offset(), prop::collection::vec(any::<u8>(), 0..48))
            .prop_map(|(offset, data)| crypto_frame(offset, &data)),
        // A CRYPTO frame that claims more data than it carries.
        1 => (offset(), offset()).prop_map(|(offset, len)| {
            let mut frame = vec![0x06];
            varint(&mut frame, offset);
            varint(&mut frame, len);
            frame
        }),
        2 => (0..32_usize).prop_map(|len| vec![0; len]),
        1 => Just(vec![0x01]),
        // ACK, with or without ECN counts, announcing any number of ranges.
        2 => (any::<bool>(), count(), prop::collection::vec(0..64_u64, 0..12)).prop_map(
            |(ecn, ranges, fields)| {
                let mut frame = vec![if ecn { 0x03 } else { 0x02 }, 0, 0];
                varint(&mut frame, ranges);
                for field in fields {
                    varint(&mut frame, field);
                }
                frame
            },
        ),
        1 => (count(), prop::collection::vec(any::<u8>(), 0..8)).prop_map(|(len, reason)| {
            let mut frame = vec![0x1c, 0, 0];
            varint(&mut frame, len);
            frame.extend(reason);
            frame
        }),
        1 => prop::collection::vec(any::<u8>(), 1..12),
    ]
}

/// Datagrams of one to three sealed packets, most of them Initial packets, around
/// [`hostile_frame`]s.
fn hostile_flight() -> impl Strategy<Value = Vec<Vec<u8>>> {
    let packet = (
        prop_oneof![4 => Just(INITIAL_V1), 1 => Just(HANDSHAKE_V1)],
        prop_oneof![9 => Just(DCID.to_vec()), 1 => prop::collection::vec(any::<u8>(), 0..=20)],
        any::<u32>(),
        prop::collection::vec(hostile_frame(), 0..8),
    )
        .prop_map(|(kind, dcid, pn, frames)| seal(kind, &dcid, pn, &frames.concat()));
    let datagram = prop::collection::vec(packet, 1..=3).prop_map(|packets| packets.concat());
    prop::collection::vec(datagram, 1..6)
}

/// A ClientHello-shaped handshake message and its bytes as CRYPTO frames: pieces in any
/// order, overlapping and repeated, then the whole message once so nothing is missing.
fn scattered_hello() -> impl Strategy<Value = (Vec<u8>, Vec<Vec<u8>>)> {
    prop::collection::vec(any::<u8>(), 0..600)
        .prop_flat_map(|body| {
            let mut message = vec![1];
            message.extend(&u32::try_from(body.len()).expect("short body").to_be_bytes()[1..]);
            message.extend(body);
            let pieces = prop::collection::vec((any::<Index>(), any::<Index>()), 0..12);
            (Just(message), pieces)
        })
        .prop_map(|(message, pieces)| {
            let mut frames: Vec<Vec<u8>> = pieces
                .into_iter()
                .map(|(start, len)| {
                    let start = start.index(message.len());
                    let end = start + len.index(message.len() - start + 1);
                    crypto_frame(start as u64, &message[start..end])
                })
                .collect();
            frames.push(crypto_frame(0, &message));
            (message, frames)
        })
}

/// Pushes every datagram into one assembler and checks each answer.
fn exercise(datagrams: &[Vec<u8>]) -> Result<Option<ClientInitial>, TestCaseError> {
    let mut assembler = InitialAssembler::new();
    let mut found = None;
    for datagram in datagrams {
        let was_complete = assembler.is_complete();
        match assembler.push(datagram) {
            Ok(Some(initial)) => {
                prop_assert!(!was_complete, "the ClientHello came out twice");
                prop_assert!(assembler.is_complete());
                let hello = initial.client_hello();
                prop_assert!(hello.len() <= MAX_CRYPTO_LEN);
                prop_assert!(hello.len() >= 4);
                prop_assert_eq!(hello[0], 1);
                let declared = usize::from(hello[1]) << 16
                    | usize::from(hello[2]) << 8
                    | usize::from(hello[3]);
                prop_assert_eq!(hello.len(), 4 + declared);
                prop_assert!(initial.dcid().len() <= 20);
                found = Some(initial);
            }
            Ok(None) => {}
            Err(error) => {
                prop_assert!(!was_complete, "a finished assembler reads nothing");
                // Every error has a message.
                prop_assert!(!error.to_string().is_empty());
            }
        }
        // The Debug form lists the received ranges; it must not grow with hostile offsets.
        let debug = format!("{assembler:?}");
        prop_assert!(debug.len() < 64 * 1024);
    }
    Ok(found)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_datagrams_are_handled(
        datagrams in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..1500), 1..4),
    ) {
        prop_assert!(exercise(&datagrams)?.is_none());
    }

    #[test]
    fn long_headers_with_random_bodies_are_handled(
        datagrams in prop::collection::vec(long_header_datagram(), 1..4),
    ) {
        exercise(&datagrams)?;
    }

    #[test]
    fn mutated_real_datagrams_are_handled(datagrams in mutated_flight()) {
        exercise(&datagrams)?;
    }

    #[test]
    fn sealed_packets_with_hostile_frames_are_handled(datagrams in hostile_flight()) {
        exercise(&datagrams)?;
    }

    #[test]
    fn a_scattered_hello_is_reassembled(
        (message, frames) in scattered_hello(),
        per_packet in 1..4_usize,
    ) {
        let datagrams: Vec<Vec<u8>> = frames
            .chunks(per_packet)
            .zip(0..)
            .map(|(frames, pn)| seal(INITIAL_V1, &DCID, pn, &frames.concat()))
            .collect();
        let initial = exercise(&datagrams)?;
        let hello = initial.as_ref().map(ClientInitial::client_hello);
        prop_assert_eq!(hello, Some(message.as_slice()));
    }
}

/// The real datagrams, unedited, still give Chrome's ClientHello: the mutation test starts
/// from input the assembler accepts.
#[test]
fn unedited_real_datagrams_complete() {
    let datagrams = real_datagrams();
    let mut assembler = InitialAssembler::new();
    assert_eq!(assembler.push(&datagrams[0]), Ok(None));
    assert!(matches!(assembler.push(&datagrams[1]), Ok(Some(_))));
    // The RFC packet belongs to another connection, but a finished assembler reads nothing.
    assert_eq!(assembler.push(&datagrams[2]), Ok(None));
    assert_eq!(
        InitialAssembler::new().push(&datagrams[2][..100]),
        Err(Error::Truncated)
    );
}
