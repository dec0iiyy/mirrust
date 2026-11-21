//! Helpers shared by the fuzz targets: input framing and checks on what the parsers return.

use quic::{ClientInitial, Error, InitialAssembler, MAX_CRYPTO_LEN, MAX_DATAGRAM_SIZES, Version};
use rustls::Side;

/// Longest connection ID QUIC v1 and v2 allow (RFC 9000 §17.2).
const MAX_CID_LEN: usize = 20;

/// Splits fuzz input into chunks, each preceded by a big-endian `u16` length; a length past the
/// end takes what is left. The seed writer in `fuzz/seeds.py` uses the same framing.
#[must_use]
pub fn split_chunks(mut data: &[u8]) -> Vec<&[u8]> {
    let mut chunks = Vec::new();
    while let Some((len, rest)) = data.split_first_chunk::<2>() {
        let len = usize::from(u16::from_be_bytes(*len)).min(rest.len());
        let (chunk, rest) = rest.split_at(len);
        chunks.push(chunk);
        data = rest;
    }
    chunks
}

/// Feeds `datagrams` to a fresh assembler and checks what its documentation promises.
///
/// # Panics
///
/// When the assembler breaks one of those promises.
pub fn assemble(datagrams: &[impl AsRef<[u8]>]) {
    let mut assembler = InitialAssembler::new();
    let mut done = false;
    let mut conflict = false;
    for datagram in datagrams {
        let datagram = datagram.as_ref();
        if let Some(dcid) = quic::destination_connection_id(datagram) {
            assert!(dcid.len() <= MAX_CID_LEN, "dcid of {} bytes", dcid.len());
            assert_eq!(datagram.get(6..6 + dcid.len()), Some(dcid));
        }
        let result = assembler.push(datagram);
        if conflict {
            assert_eq!(result, Err(Error::CryptoConflict), "a conflict is final");
            continue;
        }
        if done {
            assert_eq!(result, Ok(None), "push after the ClientHello reads nothing");
            continue;
        }
        match result {
            Ok(Some(initial)) => {
                check_initial(&initial, datagrams.len());
                assert!(assembler.is_complete());
                fingerprint_quic_hello(initial.client_hello());
                done = true;
            }
            Err(Error::CryptoConflict) => conflict = true,
            Ok(None) | Err(_) => assert!(!assembler.is_complete()),
        }
    }
}

fn check_initial(initial: &ClientInitial, datagrams: usize) {
    let hello = initial.client_hello();
    let [kind, a, b, c, ..] = *hello else {
        panic!("ClientHello of {} bytes has no header", hello.len());
    };
    assert_eq!(kind, 0x01, "handshake type");
    let body = u32::from_be_bytes([0, a, b, c]) as usize;
    assert_eq!(hello.len(), 4 + body, "message length");
    assert!(hello.len() <= MAX_CRYPTO_LEN, "{} bytes kept", hello.len());
    assert!(initial.dcid().len() <= MAX_CID_LEN);
    assert!(initial.scid().len() <= MAX_CID_LEN);
    let sizes = initial.datagram_sizes();
    assert!(!sizes.is_empty() && sizes.len() <= MAX_DATAGRAM_SIZES.min(datagrams));
}

/// Runs the fingerprints the server computes for a ClientHello that came over QUIC.
fn fingerprint_quic_hello(message: &[u8]) {
    let hello = fingerprint::ClientHello::parse(message);
    let ja4 = fingerprint::Ja4::new(&hello, fingerprint::Transport::Quic);
    assert!(ja4.hashed().starts_with('q'), "{}", ja4.hashed());
}

/// Builds a protected Initial packet (4-byte packet number, empty token, 0x40-prefixed
/// two-byte length) holding `frames` as its plaintext, as a client would.
///
/// # Panics
///
/// When `dcid` or `scid` is over 255 bytes or `frames` is over 16 KiB.
#[must_use]
pub fn seal_initial(version: Version, dcid: &[u8], scid: &[u8], pn: u32, frames: &[u8]) -> Vec<u8> {
    let (rustls_version, kind) = match version {
        Version::V2 => (rustls::quic::Version::V2, 1),
        _ => (rustls::quic::Version::V1, 0),
    };
    let keys = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(rustls::Tls13CipherSuite::quic_suite)
        .expect("TLS_AES_128_GCM_SHA256 has a QUIC suite")
        .keys(dcid, Side::Client, rustls_version)
        .local;
    let mut header = vec![0xc3 | (kind << 4)];
    header.extend(version.to_wire().to_be_bytes());
    header.push(u8::try_from(dcid.len()).expect("dcid under 256 bytes"));
    header.extend(dcid);
    header.push(u8::try_from(scid.len()).expect("scid under 256 bytes"));
    header.extend(scid);
    header.push(0); // token length
    let length = u16::try_from(4 + frames.len() + 16)
        .ok()
        .filter(|&len| len < 0x4000)
        .expect("frames under 16 KiB");
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
