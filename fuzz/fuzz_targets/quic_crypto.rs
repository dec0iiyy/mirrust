//! Decrypted Initial payloads into `quic::InitialAssembler`: frame parsing and CRYPTO stream
//! reassembly, which random datagrams cannot reach because they do not decrypt.
//!
//! Input: one selector byte (bit 0: QUIC v2), then `u16`-length-prefixed plaintext payloads.
//! Each payload is sealed into one Initial packet of one datagram, all for the same connection.

#![no_main]

use libfuzzer_sys::fuzz_target;
use quic::Version;

/// The Destination Connection ID of RFC 9001 Appendix A.
const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
/// Longest plaintext [`mirrust_fuzz::seal_initial`] takes.
const MAX_PAYLOAD: usize = 0x3fff - 4 - 16;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let version = if selector & 1 == 0 {
        Version::V1
    } else {
        Version::V2
    };
    let datagrams: Vec<Vec<u8>> = mirrust_fuzz::split_chunks(rest)
        .into_iter()
        .zip(0u32..)
        .map(|(payload, pn)| {
            let payload = &payload[..payload.len().min(MAX_PAYLOAD)];
            mirrust_fuzz::seal_initial(version, &DCID, &[], pn, payload)
        })
        .collect();
    mirrust_fuzz::assemble(&datagrams);
});
