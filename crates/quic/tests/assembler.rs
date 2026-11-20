//! Checks the assembler against RFC 9001 Appendix A.2 and against packets sealed with rustls.

use quic::{Error, InitialAssembler, Version};
use rustls::Side;

fn unhex(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn rfc_packet() -> Vec<u8> {
    unhex(include_str!("data/rfc9001_a2_protected_packet.hex"))
}

/// The ClientHello of RFC 9001 A.2: the CRYPTO frame without its 4-byte frame header.
fn rfc_client_hello() -> Vec<u8> {
    unhex(include_str!("data/rfc9001_a2_crypto_frame.hex"))[4..].to_vec()
}

const RFC_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

#[test]
fn rfc9001_a2_client_initial_decrypts_to_the_client_hello() {
    let packet = rfc_packet();
    assert_eq!(packet.len(), 1200);
    let mut assembler = InitialAssembler::new();
    let initial = assembler
        .push(&packet)
        .expect("RFC packet decrypts")
        .expect("one packet holds the whole ClientHello");
    assert_eq!(initial.version(), Version::V1);
    assert_eq!(initial.dcid(), RFC_DCID);
    assert_eq!(initial.scid(), b"");
    assert_eq!(initial.client_hello(), rfc_client_hello());
    assert_eq!(initial.client_hello().len(), 241);
    assert_eq!(initial.token_len(), 0);
    assert_eq!(initial.datagram_sizes(), [1200]);
    assert!(assembler.is_complete());
    assert_eq!(assembler.push(&packet), Ok(None));
}

#[test]
fn rfc9001_a2_with_a_flipped_bit_does_not_decrypt() {
    let mut packet = rfc_packet();
    packet[600] ^= 1;
    assert_eq!(InitialAssembler::new().push(&packet), Err(Error::Decrypt));
}

#[test]
fn truncated_and_garbage_datagrams_are_errors() {
    let packet = rfc_packet();
    for len in [1, 5, 6, 15, 20, 21, 22, 40, 1199] {
        let result = InitialAssembler::new().push(&packet[..len]);
        assert!(result.is_err(), "prefix of {len} bytes gave {result:?}");
    }
    assert_eq!(
        InitialAssembler::new().push(&[0x40, 1, 2, 3]),
        Err(Error::NoInitialPacket)
    );
    assert_eq!(
        InitialAssembler::new().push(&[]),
        Err(Error::NoInitialPacket)
    );
    let mut bad_version = packet.clone();
    bad_version[1..5].copy_from_slice(&[0xff, 0, 0, 0x1d]);
    assert_eq!(
        InitialAssembler::new().push(&bad_version),
        Err(Error::UnsupportedVersion(0xff00_001d))
    );
}

/// Builds a protected long-header packet (4-byte packet number, empty token) the way a client would.
fn seal(version: Version, kind: u8, dcid: &[u8], scid: &[u8], pn: u32, frames: &[u8]) -> Vec<u8> {
    let rustls_version = match version {
        Version::V1 => rustls::quic::Version::V1,
        _ => rustls::quic::Version::V2,
    };
    let keys = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(rustls::Tls13CipherSuite::quic_suite)
        .expect("QUIC suite")
        .keys(dcid, Side::Client, rustls_version)
        .local;
    let mut header = vec![0xc3 | (kind << 4)];
    header.extend(version.to_wire().to_be_bytes());
    header.push(u8::try_from(dcid.len()).expect("short dcid"));
    header.extend(dcid);
    header.push(u8::try_from(scid.len()).expect("short scid"));
    header.extend(scid);
    if (version == Version::V1 && kind == 0) || (version == Version::V2 && kind == 1) {
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

fn crypto_frame(offset: u16, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x06];
    frame.extend((0x4000 | offset).to_be_bytes());
    frame.extend((0x4000 | u16::try_from(data.len()).expect("short data")).to_be_bytes());
    frame.extend(data);
    frame
}

#[test]
fn reassembles_reordered_crypto_frames_across_packets_and_datagrams() {
    let hello = rfc_client_hello();
    let dcid = [7u8; 8];
    let scid = [9u8; 4];
    let (a, c) = (&hello[..70], &hello[160..]);

    // Datagram 1: an Initial with the last and first pieces (in that order) plus PADDING and PING,
    // coalesced with a Handshake packet the assembler must skip.
    let mut frames = crypto_frame(160, c);
    frames.extend([0x01, 0x00, 0x00]);
    frames.extend(crypto_frame(0, a));
    let mut first = seal(Version::V1, 0, &dcid, &scid, 0, &frames);
    first.extend(seal(Version::V1, 2, &dcid, &scid, 0, &[0x01; 8]));
    // Datagram 2: the middle piece, repeating some of the first.
    let second = seal(
        Version::V1,
        0,
        &dcid,
        &scid,
        1,
        &crypto_frame(40, &hello[40..160]),
    );

    let mut assembler = InitialAssembler::new();
    assert_eq!(assembler.push(&first), Ok(None));
    assert!(!assembler.is_complete());
    let initial = assembler.push(&second).expect("valid").expect("complete");
    assert_eq!(initial.client_hello(), hello);
    assert_eq!(initial.dcid(), dcid);
    assert_eq!(initial.scid(), scid);
}

#[test]
fn reassembles_a_quic_v2_initial() {
    let hello = rfc_client_hello();
    let packet = seal(Version::V2, 1, &RFC_DCID, &[], 2, &crypto_frame(0, &hello));
    let initial = InitialAssembler::new()
        .push(&packet)
        .expect("valid")
        .expect("complete");
    assert_eq!(initial.version(), Version::V2);
    assert_eq!(initial.client_hello(), hello);
}

#[test]
fn rejects_an_initial_from_another_connection() {
    let hello = rfc_client_hello();
    let mut assembler = InitialAssembler::new();
    let first = seal(
        Version::V1,
        0,
        &[1; 8],
        &[],
        0,
        &crypto_frame(0, &hello[..100]),
    );
    let other = seal(
        Version::V1,
        0,
        &[2; 8],
        &[],
        1,
        &crypto_frame(100, &hello[100..]),
    );
    assert_eq!(assembler.push(&first), Ok(None));
    assert_eq!(assembler.push(&other), Err(Error::ConnectionChanged));
}

#[test]
fn a_datagram_of_one_byte_frames_with_gaps_is_rejected_quickly() {
    // 170 one-byte CRYPTO frames at every other offset: each would be its own range.
    let frames: Vec<u8> = (0..170_u16)
        .flat_map(|i| crypto_frame(2 * i + 1, &[0xaa]))
        .collect();
    let datagram = seal(Version::V1, 0, &[5; 8], &[], 0, &frames);
    assert!(datagram.len() <= 1200, "fits one datagram");

    let mut assembler = InitialAssembler::new();
    let started = std::time::Instant::now();
    assert_eq!(assembler.push(&datagram), Err(Error::TooManyCryptoRanges));
    // Linear work takes microseconds; the bound only catches a return to rebuilding the list
    // for every frame while staying clear of a slow CI machine.
    assert!(
        started.elapsed() < std::time::Duration::from_millis(250),
        "took {:?}",
        started.elapsed()
    );
    assert!(!assembler.is_complete());
}

#[test]
fn a_hello_in_many_pieces_with_gaps_still_reassembles() {
    let hello = rfc_client_hello();
    let pieces: Vec<(u16, &[u8])> = hello
        .chunks(8)
        .enumerate()
        .map(|(i, piece)| (u16::try_from(i * 8).expect("small offset"), piece))
        .collect();
    assert_eq!(pieces.len(), 31);
    let mut assembler = InitialAssembler::new();
    // Even pieces first: 16 separate ranges, then the odd ones fill the gaps.
    for (parity, pn) in [(0, 0), (1, 1)] {
        let frames: Vec<u8> = pieces
            .iter()
            .skip(parity)
            .step_by(2)
            .flat_map(|&(offset, piece)| crypto_frame(offset, piece))
            .collect();
        let datagram = seal(Version::V1, 0, &[6; 8], &[], pn, &frames);
        match assembler.push(&datagram).expect("valid") {
            None => assert_eq!(parity, 0),
            Some(initial) => {
                assert_eq!(parity, 1);
                assert_eq!(initial.client_hello(), hello);
            }
        }
    }
    assert!(assembler.is_complete());
}

#[test]
fn other_bytes_for_crypto_data_already_received_end_the_assembly_for_good() {
    let hello = rfc_client_hello();
    let dcid = [7u8; 8];
    let mut assembler = InitialAssembler::new();
    let first = seal(
        Version::V1,
        0,
        &dcid,
        &[],
        0,
        &crypto_frame(0, &hello[..100]),
    );
    assert_eq!(assembler.push(&first), Ok(None));

    // The first 100 bytes again with another cipher suite list, and the rest: a server's QUIC
    // stack may hand its TLS code either copy of the start (RFC 9000 section 2.2 forbids
    // sending this), so no ClientHello is reported for the connection.
    let mut decoy = hello.clone();
    decoy[50] ^= 0xff;
    let second = seal(Version::V1, 0, &dcid, &[], 1, &crypto_frame(0, &decoy));
    assert_eq!(assembler.push(&second), Err(Error::CryptoConflict));
    assert!(!assembler.is_complete());

    // Not even from an honest copy afterwards.
    let third = seal(Version::V1, 0, &dcid, &[], 2, &crypto_frame(0, &hello));
    assert_eq!(assembler.push(&third), Err(Error::CryptoConflict));
}

#[test]
fn a_retransmitted_crypto_frame_with_the_same_bytes_is_fine() {
    let hello = rfc_client_hello();
    let dcid = [7u8; 8];
    let mut assembler = InitialAssembler::new();
    let first = seal(
        Version::V1,
        0,
        &dcid,
        &[],
        0,
        &crypto_frame(0, &hello[..100]),
    );
    assert_eq!(assembler.push(&first), Ok(None));
    assert_eq!(assembler.push(&first), Ok(None));
    let second = seal(Version::V1, 0, &dcid, &[], 1, &crypto_frame(0, &hello));
    let initial = assembler
        .push(&second)
        .expect("no conflict")
        .expect("complete");
    assert_eq!(initial.client_hello(), hello);
}

#[test]
fn a_malformed_packet_behind_an_initial_does_not_cost_the_client_hello() {
    let hello = rfc_client_hello();
    let dcid = [7u8; 8];
    let mut datagram = seal(Version::V1, 0, &dcid, &[], 0, &crypto_frame(0, &hello));
    // A long header of QUIC v1 that ends inside its connection ID.
    datagram.extend([0xc0, 0, 0, 0, 1, 20, 1, 2, 3]);
    let initial = InitialAssembler::new()
        .push(&datagram)
        .expect("the Initial packet in front was read")
        .expect("and it holds the whole ClientHello");
    assert_eq!(initial.client_hello(), hello);
    assert_eq!(initial.datagram_sizes(), [datagram.len()]);

    // In front of the Initial packet it is an error, as before.
    let mut reversed = vec![0xc0, 0, 0, 0, 1, 20, 1, 2, 3];
    reversed.extend(seal(
        Version::V1,
        0,
        &dcid,
        &[],
        0,
        &crypto_frame(0, &hello),
    ));
    assert!(InitialAssembler::new().push(&reversed).is_err());
}
