//! Property tests: `Parser::feed` takes any bytes in any chunking, what it keeps is bounded,
//! and the Akamai fingerprint and request summary of whatever was parsed can be computed.
//!
//! Inputs are arbitrary bytes after the preface, random frames (so the frame readers and the
//! HPACK decoder run instead of the length field stalling nearly every case), and the
//! sessions of `corpus/h2.jsonl` with bytes flipped, cut off and inserted.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http2::{
    DEFAULT_MAX_INPUT, Error, Http2Request, MAX_FRAMES, MAX_HEADER_BYTES, PREFACE, Parser, Status,
    akamai_fingerprint, akamai_fingerprint_hash,
};
use proptest::prelude::*;
use proptest::sample::Index;
use serde_json::Value;

const SESSIONS: &str = include_str!("../../../corpus/h2.jsonl");

const HEADERS: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

fn corpus() -> Vec<Vec<u8>> {
    SESSIONS
        .lines()
        .map(|line| {
            let input: Value = serde_json::from_str(line).expect("corpus line is JSON");
            STANDARD
                .decode(input["b64"].as_str().expect("corpus b64"))
                .expect("corpus base64 is valid")
        })
        .collect()
}

/// One edit of a session.
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

/// A real session from the corpus after one to four edits.
fn mutated_session() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::sample::select(corpus()),
        prop::collection::vec(mutation(), 1..=4),
    )
        .prop_map(|(mut session, mutations)| {
            for mutation in &mutations {
                apply(&mut session, mutation);
            }
            session
        })
}

/// An HPACK integer (RFC 7541 section 5.1) behind `flags` in the first byte.
fn hpack_int(out: &mut Vec<u8>, flags: u8, prefix_bits: u8, mut value: usize) {
    let max = (1_usize << prefix_bits) - 1;
    if value < max {
        out.push(flags | u8::try_from(value).expect("below the prefix"));
        return;
    }
    out.push(flags | u8::try_from(max).expect("a prefix fits a byte"));
    value -= max;
    while value >= 128 {
        out.push(0x80 | u8::try_from(value % 128).expect("seven bits"));
        value /= 128;
    }
    out.push(u8::try_from(value).expect("seven bits"));
}

fn hpack_string(out: &mut Vec<u8>, bytes: &[u8]) {
    hpack_int(out, 0, 7, bytes.len());
    out.extend(bytes);
}

/// One HPACK representation.
#[derive(Debug, Clone)]
enum Field {
    /// A static or dynamic table entry by index.
    Indexed(usize),
    /// A literal that is added to the dynamic table, with a value of this many bytes.
    Stored(Vec<u8>, usize),
    /// A literal that is not added.
    Plain(Vec<u8>, Vec<u8>),
    /// A dynamic table size update.
    TableSize(usize),
    /// Anything.
    Raw(Vec<u8>),
}

fn encode(fields: Vec<Field>) -> Vec<u8> {
    let mut block = Vec::new();
    for field in fields {
        match field {
            Field::Indexed(index) => hpack_int(&mut block, 0x80, 7, index),
            Field::Stored(name, len) => {
                block.push(0x40);
                hpack_string(&mut block, &name);
                hpack_string(&mut block, &vec![b'v'; len]);
            }
            Field::Plain(name, value) => {
                block.push(0x00);
                hpack_string(&mut block, &name);
                hpack_string(&mut block, &value);
            }
            Field::TableSize(size) => hpack_int(&mut block, 0x20, 5, size),
            Field::Raw(bytes) => block.extend(bytes),
        }
    }
    block
}

/// A header block that decodes: one stored literal, then entries that are in the tables,
/// most of them the stored one again. This is the shape that makes a small block decode to
/// a large header list.
fn repeating_block() -> impl Strategy<Value = Vec<u8>> {
    let name = prop::collection::vec(b'a'..=b'z', 1..12);
    let repeat =
        prop_oneof![3 => Just(Field::Indexed(62)), 1 => (1..=62_usize).prop_map(Field::Indexed)];
    (name, 0..4000_usize, prop::collection::vec(repeat, 0..256)).prop_map(
        |(name, len, mut fields)| {
            fields.insert(0, Field::Stored(name, len));
            encode(fields)
        },
    )
}

/// A header block of any representations, valid or not.
fn header_block() -> impl Strategy<Value = Vec<u8>> {
    let name = prop::collection::vec(prop_oneof![Just(b':'), b'a'..=b'z'], 0..12);
    let field = prop_oneof![
        4 => (1..80_usize).prop_map(Field::Indexed),
        // The first dynamic entry, referenced again and again.
        4 => Just(Field::Indexed(62)),
        2 => (name.clone(), 0..4000_usize).prop_map(|(name, len)| Field::Stored(name, len)),
        2 => (name, prop::collection::vec(any::<u8>(), 0..24))
            .prop_map(|(name, value)| Field::Plain(name, value)),
        1 => prop_oneof![0..8192_usize, 0..1_usize << 28].prop_map(Field::TableSize),
        1 => prop::collection::vec(any::<u8>(), 1..8).prop_map(Field::Raw),
    ];
    prop::collection::vec(field, 0..96).prop_map(encode)
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("short payload");
    let mut out = len.to_be_bytes()[1..].to_vec();
    out.push(kind);
    out.push(flags);
    out.extend(stream.to_be_bytes());
    out.extend(payload);
    out
}

/// A frame of any type with a payload that is often the right size for it.
fn any_frame() -> impl Strategy<Value = Vec<u8>> {
    let payload = prop_oneof![
        prop::collection::vec(any::<u8>(), 0..48),
        // SETTINGS-shaped: whole six-byte entries with small ids.
        prop::collection::vec((0..12_u8, any::<u32>()), 0..8).prop_map(|entries| {
            entries
                .into_iter()
                .flat_map(|(id, value)| [0, id].into_iter().chain(value.to_be_bytes()))
                .collect()
        }),
        prop::sample::select(vec![4_usize, 5, 8])
            .prop_flat_map(|len| { prop::collection::vec(any::<u8>(), len) }),
    ];
    (
        prop_oneof![4 => 0..=9_u8, 1 => any::<u8>()],
        // END_STREAM rarely, so more than one frame is usually read.
        prop_oneof![3 => any::<u8>().prop_map(|flags| flags & !0x1), 1 => any::<u8>()],
        prop_oneof![Just(0_u32), Just(1), Just(3), any::<u32>()],
        payload,
    )
        .prop_map(|(kind, flags, stream, payload)| frame(kind, flags, stream, &payload))
}

/// A HEADERS frame with a generated header block, complete in one frame.
fn headers_frame() -> impl Strategy<Value = Vec<u8>> {
    let block = prop_oneof![header_block(), repeating_block()];
    (block, any::<bool>()).prop_map(|(block, end_stream)| {
        frame(HEADERS, FLAG_END_HEADERS | u8::from(end_stream), 1, &block)
    })
}

/// The preface and a run of frames.
fn session() -> impl Strategy<Value = Vec<u8>> {
    let frames = prop_oneof![3 => any_frame(), 1 => headers_frame()];
    prop::collection::vec(frames, 0..12).prop_map(|frames| {
        let mut bytes = PREFACE.to_vec();
        bytes.extend(frames.into_iter().flatten());
        bytes
    })
}

/// Chunk lengths to cut a session by; they repeat when the session is longer.
fn chunking() -> impl Strategy<Value = Vec<usize>> {
    prop::collection::vec(1..64_usize, 1..16)
}

/// Feeds `bytes` in pieces of the given lengths until the parser answers or fails.
///
/// The input cap is lifted: these tests are about what parsing keeps, and a session over the
/// default cap fails as `TooLarge` when fed whole but on its first bad frame when fed in pieces.
fn feed(bytes: &[u8], pieces: &[usize]) -> (Result<Status, Error>, Parser) {
    let mut parser = Parser::with_max_input(1 << 20);
    let mut rest = bytes;
    let mut status = Ok(Status::Incomplete);
    for &len in pieces.iter().cycle() {
        if rest.is_empty() || status != Ok(Status::Incomplete) {
            break;
        }
        let (piece, tail) = rest.split_at(len.min(rest.len()));
        rest = tail;
        status = parser.feed(piece);
    }
    (status, parser)
}

/// Feeds `bytes` whole and in pieces, checks both runs agree and that everything computed
/// from the parsed frames is well-formed.
fn exercise(bytes: &[u8], pieces: &[usize]) -> Result<(), TestCaseError> {
    let (whole_status, whole) = feed(bytes, &[bytes.len().max(1)]);
    let (status, mut parser) = feed(bytes, pieces);
    prop_assert_eq!(&status, &whole_status);
    prop_assert_eq!(parser.frames(), whole.frames());

    let frames = parser.frames();
    // Every frame takes at least its nine-byte header.
    prop_assert!(frames.len() <= bytes.len() / 9);
    let payload_bytes: usize = frames.iter().map(|f| f.payload.len()).sum();
    prop_assert!(payload_bytes <= bytes.len());
    // A decoded byte is at most one character of a header line.
    let header_chars: usize = frames
        .iter()
        .flat_map(|f| &f.headers)
        .map(|line| line.chars().count())
        .sum();
    prop_assert!(
        header_chars <= MAX_HEADER_BYTES,
        "{} bytes of input decoded to {} bytes of headers",
        bytes.len(),
        header_chars
    );
    prop_assert_eq!(akamai_fingerprint_hash(frames).len(), 32);
    prop_assert!(akamai_fingerprint(frames).matches('|').count() >= 3);

    // A caller that keeps feeding after the answer or an error gets no panic either, and
    // an answer stays an answer.
    let parsed = frames.len();
    let again = parser.feed(bytes);
    if status == Ok(Status::Complete) {
        prop_assert_eq!(again, Ok(Status::Complete));
        prop_assert_eq!(parser.frames().len(), parsed);
    }

    let request = Http2Request::new(parser);
    let details = &request.details;
    prop_assert_eq!(
        &details.akamai_fingerprint_hash,
        &akamai_fingerprint_hash(&details.sent_frames)
    );
    prop_assert!(serde_json::to_string(details).is_ok());
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_after_the_preface_parse(
        tail in prop::collection::vec(any::<u8>(), 0..512),
        pieces in chunking(),
    ) {
        let bytes = [&PREFACE[..], &tail].concat();
        exercise(&bytes, &pieces)?;
    }

    #[test]
    fn arbitrary_bytes_without_a_preface_parse(
        bytes in prop::collection::vec(any::<u8>(), 0..64),
        pieces in chunking(),
    ) {
        exercise(&bytes, &pieces)?;
    }

    #[test]
    fn random_frames_parse(bytes in session(), pieces in chunking()) {
        exercise(&bytes, &pieces)?;
    }

    #[test]
    fn repeated_table_entries_stay_bounded(
        blocks in prop::collection::vec(repeating_block(), 1..4),
        pieces in chunking(),
    ) {
        let mut bytes = PREFACE.to_vec();
        for block in &blocks {
            bytes.extend(frame(HEADERS, FLAG_END_HEADERS, 1, block));
        }
        exercise(&bytes, &pieces)?;
    }

    #[test]
    fn mutated_real_sessions_parse(bytes in mutated_session(), pieces in chunking()) {
        exercise(&bytes, &pieces)?;
    }
}

/// The HPACK bomb: one 4000-byte literal stored in the dynamic table, then one byte per
/// repeat. These 64 KiB of input used to decode to 240 MB of header lines.
#[test]
fn a_block_repeating_one_table_entry_is_rejected() {
    let mut block = vec![0x40];
    hpack_string(&mut block, b"x");
    hpack_string(&mut block, &[b'v'; 4000]);
    // 0xbe: the indexed representation of entry 62, the first of the dynamic table.
    block.resize(block.len() + 60_000, 0xbe);
    let mut bytes = PREFACE.to_vec();
    bytes.extend(frame(HEADERS, FLAG_END_HEADERS | 0x1, 1, &block));

    let mut parser = Parser::new();
    assert_eq!(parser.feed(&bytes), Err(Error::HeadersTooLarge));
    assert_eq!(parser.frames(), []);
}

/// The cap is on the whole connection, not on each HEADERS frame.
#[test]
fn header_lines_are_capped_across_frames() {
    let mut block = vec![0x00];
    hpack_string(&mut block, b"x");
    hpack_string(&mut block, &[b'v'; 4000]);
    let mut bytes = PREFACE.to_vec();
    for _ in 0..=MAX_HEADER_BYTES / 4000 {
        bytes.extend(frame(HEADERS, FLAG_END_HEADERS, 1, &block));
    }

    // The default input cap is the same 64 KiB, so lift it to reach the header cap.
    let mut parser = Parser::with_max_input(1 << 20);
    assert_eq!(parser.feed(&bytes), Err(Error::HeadersTooLarge));
    assert_eq!(parser.frames().len(), MAX_HEADER_BYTES / 4003);
}

/// 1 MiB of empty frames used to become about 116,000 records, then JSON, then a response.
#[test]
fn a_flood_of_empty_frames_is_rejected_with_a_bounded_record_list() {
    let empty = frame(0x4, 0, 0, &[]);
    let mut bytes = PREFACE.to_vec();
    while bytes.len() < 1 << 20 {
        bytes.extend(&empty);
    }
    let started = std::time::Instant::now();

    // The whole megabyte at once: over the input cap, nothing is parsed.
    let mut parser = Parser::new();
    assert_eq!(parser.feed(&bytes), Err(Error::TooLarge));
    assert!(parser.frames().len() <= MAX_FRAMES);

    // Within the input cap, the frame cap is what stops it.
    let mut parser = Parser::new();
    let within_cap = &bytes[..DEFAULT_MAX_INPUT];
    assert_eq!(parser.feed(within_cap), Err(Error::TooManyFrames));
    assert_eq!(parser.frames().len(), MAX_FRAMES);

    // Fed in pieces, as the server reads it, the flood stops at the same place.
    let mut parser = Parser::new();
    let outcome = bytes
        .chunks(16 * 1024)
        .map(|piece| parser.feed(piece))
        .find(Result::is_err);
    assert_eq!(outcome, Some(Err(Error::TooManyFrames)));
    assert_eq!(parser.frames().len(), MAX_FRAMES);
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn exactly_the_frame_cap_is_accepted() {
    let mut bytes = PREFACE.to_vec();
    for _ in 1..MAX_FRAMES {
        bytes.extend(frame(0x4, 0, 0, &[]));
    }
    // The last allowed frame is the one that ends the request.
    bytes.extend(frame(0x1, FLAG_END_HEADERS | 0x1, 1, &[0x82]));
    let mut parser = Parser::new();
    assert_eq!(parser.feed(&bytes), Ok(Status::Complete));
    assert_eq!(parser.frames().len(), MAX_FRAMES);
}

/// After an error the parser keeps answering with that error, not with whatever the next
/// bytes would have caused (a second feed used to report `TooLarge` after `HeaderDecode`).
#[test]
fn the_first_error_is_latched() {
    // An indexed field that points past the dynamic table fails HPACK decoding.
    let mut bytes = PREFACE.to_vec();
    bytes.extend(frame(HEADERS, FLAG_END_HEADERS, 1, &[0xff, 0x7f]));
    let mut parser = Parser::with_max_input(bytes.len() + 4);
    assert_eq!(parser.feed(&bytes), Err(Error::HeaderDecode));
    let frames = parser.frames().len();

    // Over the input cap, with a bad preface's worth of bytes, or valid: always the first error.
    assert_eq!(parser.feed(&[0; 16]), Err(Error::HeaderDecode));
    assert_eq!(parser.feed(&bytes), Err(Error::HeaderDecode));
    assert_eq!(parser.feed(&[]), Err(Error::HeaderDecode));
    assert_eq!(parser.frames().len(), frames);
}
