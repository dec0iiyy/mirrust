//! A raw handshake message into `fingerprint::ClientHello::parse` and `parse_peet`, then every
//! fingerprint and detail the server computes from the result.

#![no_main]

use fingerprint::{ClientHello, Ja3, Ja4, Ja4Peet, PeetPrint, Transport};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let hello = ClientHello::parse(data);
    check_hello(&hello, data);
    for transport in [Transport::Tcp, Transport::Quic, Transport::Dtls] {
        let ja4 = Ja4::new(&hello, transport);
        let a = check_ja4(ja4.hashed(), transport);
        check_ja4(ja4.original(), transport);
        assert!(ja4.raw().starts_with(&format!("{a}_")), "{}", ja4.raw());
        assert!(ja4.raw_original().starts_with(&format!("{a}_")));
        let _ = fingerprint::known::lookup(&ja4);
    }

    let peet = ClientHello::parse_peet(data);
    check_hello(&peet, data);
    if [0x0303, 0x0304].contains(&hello.legacy_version) {
        assert_eq!(
            peet, hello,
            "parse_peet reads TLS 1.2 and 1.3 hellos like parse"
        );
    } else {
        assert!(peet.random.is_empty() && peet.extensions.is_empty());
    }

    let ja3 = Ja3::new(&peet);
    assert_eq!(ja3.text().matches(',').count(), 4, "{}", ja3.text());
    assert!(is_lower_hex(ja3.hash(), 32), "{}", ja3.hash());
    let peetprint = PeetPrint::new(&peet);
    assert!(is_lower_hex(peetprint.hash(), 32));
    let negotiated = data
        .get(..2)
        .map_or(0x0304, |v| u16::from_be_bytes([v[0], v[1]]));
    let ja4_peet = Ja4Peet::new(&peet, negotiated, Transport::Tcp);
    let parts: Vec<&str> = ja4_peet.hashed().split('_').collect();
    assert!(
        matches!(parts[..], [_, b, c] if is_lower_hex(b, 12) && is_lower_hex(c, 12)),
        "{}",
        ja4_peet.hashed()
    );
    let _ = ja4_peet.raw();

    assert_eq!(peet.readable_ciphers().len(), peet.cipher_suites.len());
    serde_json::to_string(&peet.extension_details()).expect("details serialize");
});

/// Checks the bounds the wire format puts on each field and that nothing outgrows the input.
fn check_hello(hello: &ClientHello, data: &[u8]) {
    if data.first() != Some(&1) {
        assert_eq!(*hello, ClientHello::default(), "not a ClientHello");
        return;
    }
    if let Some(&[a, b, c]) = data.get(1..4) {
        assert_eq!(hello.length, u32::from_be_bytes([0, a, b, c]));
    }
    assert!(matches!(hello.random.len(), 0 | 32));
    assert!(hello.session_id.len() <= 255);
    assert!(hello.compression_methods.len() <= 255);
    let extension_bytes: usize = hello.extensions.iter().map(|e| e.data.len() + 4).sum();
    assert!(
        extension_bytes <= data.len(),
        "{extension_bytes} extension bytes"
    );
    let alpn_bytes: usize = hello.alpn.iter().map(Vec::len).sum();
    assert!(alpn_bytes <= extension_bytes);
    assert!(2 * hello.cipher_suites.len() <= data.len());
    for list in [
        &hello.supported_groups,
        &hello.signature_algorithms,
        &hello.supported_versions,
        &hello.cert_compression_algorithms,
    ] {
        assert!(2 * list.len() <= extension_bytes);
    }
}

/// Checks the shape of a hashed JA4 (`a_b_c`, part a ten characters, b and c 12 hex digits)
/// and returns part a.
fn check_ja4(ja4: &str, transport: Transport) -> &str {
    let parts: Vec<&str> = ja4.split('_').collect();
    let [a, b, c] = parts[..] else {
        panic!("JA4 {ja4} is not three parts");
    };
    assert!(is_lower_hex(b, 12) && is_lower_hex(c, 12), "{ja4}");
    let a_bytes = a.as_bytes();
    assert_eq!(a_bytes.len(), 10, "{ja4}");
    let letter = match transport {
        Transport::Quic => b'q',
        Transport::Dtls => b'd',
        Transport::Tcp => b't',
    };
    assert_eq!(a_bytes[0], letter, "{ja4}");
    assert!(matches!(a_bytes[3], b'd' | b'i'), "{ja4}");
    assert!(a_bytes[4..8].iter().all(u8::is_ascii_digit), "{ja4}");
    assert!(a_bytes[8..].iter().all(u8::is_ascii_alphanumeric), "{ja4}");
    a
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
