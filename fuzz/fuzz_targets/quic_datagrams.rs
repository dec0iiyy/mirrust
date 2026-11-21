//! Raw UDP datagrams into `quic::InitialAssembler`: long-header parsing, Initial key
//! derivation, header protection and AEAD failure paths. Input: `u16`-length-prefixed datagrams.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    mirrust_fuzz::assemble(&mirrust_fuzz::split_chunks(data));
});
