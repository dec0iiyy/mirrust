//! Replays the two Initial datagrams Chrome Canary 160 sent to a local listener
//! (`examples/capture.rs`, SNI `tls.example`) and checks the ClientHello and its JA4s.

use fingerprint::{ClientHello, Ja4, Ja4Peet, Transport};
use quic::{InitialAssembler, Version};

fn unhex(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn datagrams() -> Vec<Vec<u8>> {
    include_str!("data/chrome160_datagrams.hex")
        .lines()
        .map(unhex)
        .collect()
}

#[test]
fn chrome_post_quantum_client_hello_spans_two_datagrams() {
    let datagrams = datagrams();
    assert_eq!(datagrams.len(), 2);
    let mut assembler = InitialAssembler::new();
    assert_eq!(assembler.push(&datagrams[0]), Ok(None));
    let initial = assembler
        .push(&datagrams[1])
        .expect("Chrome's Initial decrypts")
        .expect("two datagrams complete the ClientHello");
    assert_eq!(initial.version(), Version::V1);
    assert_eq!(initial.dcid().len(), 8);
    assert_eq!(initial.scid(), b"");
    assert_eq!(initial.token_len(), 0);
    assert_eq!(initial.datagram_sizes(), [1250, 1250]);
    assert_eq!(
        initial.client_hello(),
        unhex(include_str!("data/chrome160_client_hello.hex"))
    );
    assert_eq!(initial.client_hello().len(), 1918);
}

#[test]
fn chrome_datagrams_in_reverse_order_give_the_same_client_hello() {
    let datagrams = datagrams();
    let mut assembler = InitialAssembler::new();
    assert_eq!(assembler.push(&datagrams[1]), Ok(None));
    let initial = assembler
        .push(&datagrams[0])
        .expect("valid")
        .expect("complete");
    assert_eq!(
        initial.client_hello(),
        unhex(include_str!("data/chrome160_client_hello.hex"))
    );
}

#[test]
fn chrome_quic_ja4_matches_foxio_and_peet() {
    let message = unhex(include_str!("data/chrome160_client_hello.hex"));
    let ja4 = Ja4::new(&ClientHello::parse(&message), Transport::Quic);
    assert_eq!(ja4.hashed(), "q13d0312h3_55b375c5d22e_178839b6cec1");
    // tls.peet.ws's JA4 for QUIC on the same bytes.
    let peet = Ja4Peet::new(&ClientHello::parse_peet(&message), 0x0304, Transport::Quic);
    assert_eq!(peet.hashed(), "q13d312_55b375c5d22e_178839b6cec1");
}
