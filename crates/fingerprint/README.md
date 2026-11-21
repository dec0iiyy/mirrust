# mirrust-fingerprint

TLS client fingerprints from a raw ClientHello, without I/O:

- **JA3**, text and MD5.
- **JA4** as the FoxIO specification defines it, with the `_r`, `_o` and `_ro` forms.
- The **JA4 variant** and **PeetPrint** exactly as [tls.peet.ws](https://tls.peet.ws) reports
  them, quirks included, so the two compare directly.
- Readable IANA names for cipher suites and extensions.
- A small built-in dataset of known clients (Chrome, Firefox, Safari, curl, Go, Python,
  Node.js, Java, okhttp, rustls and a few more) to look a JA4 up in, and a minimal reader of
  what a `User-Agent` claims.

The parser is lenient: it never fails, and fields a truncated message cannot hold stay empty.
It is the library behind the [mirrust](https://github.com/dec0iiyy/mirrust) server. The
library name is `fingerprint`.

```rust
use fingerprint::{ClientHello, Ja3, Ja4, Transport};

// A ClientHello handshake message from its type byte (0x01), without the record header.
fn print_fingerprints(message: &[u8]) {
    let hello = ClientHello::parse(message);
    let ja4 = Ja4::new(&hello, Transport::Tcp);
    println!("JA4 {}", ja4.hashed());
    println!("JA3 {}", Ja3::new(&hello).hash());
    if let Some(client) = fingerprint::known::lookup(&ja4).client() {
        println!("looks like {} {}", client.family(), client.version());
    }
}
```

How each value is computed, field by field: [docs/fingerprints.md](https://github.com/dec0iiyy/mirrust/blob/main/docs/fingerprints.md).

## License

GPL-3.0-only. A program that links this crate and is distributed must be distributed under
the GPL-3.0 too, with its source.
