use std::borrow::Cow;

use crate::{
    ClientHello, Transport,
    grease::is_grease,
    ja3::{non_grease_ciphers, non_grease_extensions},
    peetprint::protocols,
    text::{join, sha256_12},
};

const SERVER_NAME: u16 = 0x0000;
const ALPN: u16 = 0x0010;

/// JA4 as tls.peet.ws reports it, hashed and raw; we match it for comparability.
///
/// It differs from the FoxIO specification, which [`crate::Ja4`] follows, in its first part:
/// an empty cipher or extension list counts as 1, the SNI flag is always `d`, and the counts
/// are not zero-padded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ja4Peet {
    hashed: String,
    raw: String,
}

impl Ja4Peet {
    /// Computes tls.peet.ws's JA4 from a ClientHello read with [`ClientHello::parse_peet`] and the TLS version the server negotiated.
    #[must_use]
    pub fn new(hello: &ClientHello, negotiated_version: u16, transport: Transport) -> Self {
        let a = part_a(hello, negotiated_version, transport);
        let b = part_b(hello);
        let c = part_c(hello);
        Self {
            hashed: format!("{a}_{}_{}", sha256_12(&b), sha256_12(&c)),
            raw: format!("{a}_{b}_{c}"),
        }
    }

    /// `JA4`: part a, then the truncated SHA-256 of parts b and c.
    #[must_use]
    pub fn hashed(&self) -> &str {
        &self.hashed
    }

    /// `JA4_r`: all three parts in clear.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }
}

fn part_a(hello: &ClientHello, negotiated_version: u16, transport: Transport) -> String {
    let transport = transport.letter();
    let version: Cow<'static, str> = match negotiated_version {
        0x0301 => "10".into(),
        0x0302 => "11".into(),
        0x0303 => "12".into(),
        0x0304 => "13".into(),
        other => other.to_string().into(),
    };
    // tls.peet.ws counts by splitting the JA3 field on `-`, so an empty list counts as 1.
    let ciphers = non_grease_ciphers(hello).count().max(1);
    let extensions = non_grease_extensions(hello).count().max(1);
    let alpn = match protocols(hello).first() {
        Some(&"2") => "h2",
        Some(_) => "h1",
        None => "",
    };
    // tls.peet.ws always writes `d` (domain), with or without SNI, and no zero padding.
    format!("{transport}{version}d{ciphers}{extensions}{alpn}")
}

/// Sorted cipher suites in hex; `0000` when there are none.
fn part_b(hello: &ClientHello) -> String {
    let mut ciphers: Vec<u16> = non_grease_ciphers(hello).collect();
    if ciphers.is_empty() {
        ciphers.push(0);
    }
    ciphers.sort_unstable();
    join(ciphers.iter().map(|c| format!("{c:04x}")), ",")
}

/// Sorted extensions without SNI and ALPN, `_`, signature algorithms in the client's order;
/// `0000` for the algorithms when the client sent none.
fn part_c(hello: &ClientHello) -> String {
    let mut extensions: Vec<u16> = non_grease_extensions(hello)
        .filter(|&k| k != SERVER_NAME && k != ALPN)
        .collect();
    extensions.sort_unstable();
    let algorithms: Vec<u16> = if hello.signature_algorithms.is_empty() {
        vec![0]
    } else {
        hello
            .signature_algorithms
            .iter()
            .copied()
            .filter(|&s| !is_grease(s))
            .collect()
    };
    format!(
        "{}_{}",
        join(extensions.iter().map(|e| format!("{e:04x}")), ","),
        join(algorithms.iter().map(|s| format!("{s:04x}")), ","),
    )
}
