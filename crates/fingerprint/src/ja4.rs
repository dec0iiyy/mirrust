//! JA4 per the FoxIO specification (`technical_details/JA4.md` in FoxIO-LLC/ja4).

use crate::{
    ClientHello, Extension,
    grease::is_grease,
    text::{join, sha256_12},
};

const SERVER_NAME: u16 = 0x0000;
const SIGNATURE_ALGORITHMS: u16 = 0x000d;
const ALPN: u16 = 0x0010;
const SUPPORTED_VERSIONS: u16 = 0x002b;
/// What the specification prints for a hash of an empty list.
const EMPTY_HASH: &str = "000000000000";
/// Counts above this print as 99.
const MAX_COUNT: usize = 99;

/// Transport the ClientHello arrived on, the first character of JA4.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Transport {
    /// TLS over TCP: `t`.
    #[default]
    Tcp,
    /// QUIC: `q`.
    Quic,
    /// DTLS: `d`.
    Dtls,
}

impl Transport {
    pub(crate) const fn letter(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Quic => 'q',
            Self::Dtls => 'd',
        }
    }
}

/// The JA4 TLS client fingerprint in its four forms.
///
/// GREASE is ignored everywhere. The sorted forms drop SNI and ALPN from the extension list;
/// the original-order forms keep every extension in the client's order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ja4 {
    hashed: String,
    raw: String,
    original: String,
    raw_original: String,
}

impl Ja4 {
    /// Computes JA4 from a ClientHello read with [`ClientHello::parse`].
    #[must_use]
    pub fn new(hello: &ClientHello, transport: Transport) -> Self {
        let ciphers: Vec<u16> = non_grease(hello.cipher_suites.iter().copied());
        let extensions: Vec<u16> = non_grease(hello.extensions.iter().map(|e| e.kind));
        let algorithms = hex_list(&signature_algorithms(hello));

        let a = format!(
            "{}{}{}{:02}{:02}{}",
            transport.letter(),
            version(hello),
            if find(hello, SERVER_NAME).is_some() {
                'd'
            } else {
                'i'
            },
            ciphers.len().min(MAX_COUNT),
            extensions.len().min(MAX_COUNT),
            alpn(hello),
        );

        let mut sorted_ciphers = ciphers.clone();
        sorted_ciphers.sort_unstable();
        let mut sorted_extensions: Vec<u16> = extensions
            .iter()
            .copied()
            .filter(|&k| k != SERVER_NAME && k != ALPN)
            .collect();
        sorted_extensions.sort_unstable();

        let b = hex_list(&sorted_ciphers);
        let c = with_algorithms(hex_list(&sorted_extensions), &algorithms);
        let b_original = hex_list(&ciphers);
        let c_original = with_algorithms(hex_list(&extensions), &algorithms);

        Self {
            hashed: format!("{a}_{}_{}", hash(&b), hash(&c)),
            raw: format!("{a}_{b}_{c}"),
            original: format!("{a}_{}_{}", hash(&b_original), hash(&c_original)),
            raw_original: format!("{a}_{b_original}_{c_original}"),
        }
    }

    /// `JA4`: part a, then the truncated SHA-256 of the sorted parts b and c.
    #[must_use]
    pub fn hashed(&self) -> &str {
        &self.hashed
    }

    /// `JA4_r`: the sorted parts in clear.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// `JA4_o`: hashed, with ciphers and extensions in the client's order.
    #[must_use]
    pub fn original(&self) -> &str {
        &self.original
    }

    /// `JA4_ro`: in clear, with ciphers and extensions in the client's order.
    #[must_use]
    pub fn raw_original(&self) -> &str {
        &self.raw_original
    }
}

fn non_grease(values: impl Iterator<Item = u16>) -> Vec<u16> {
    values.filter(|&v| !is_grease(v)).collect()
}

fn hex_list(values: &[u16]) -> String {
    join(values.iter().map(|v| format!("{v:04x}")), ",")
}

/// Part c: extensions, then `_` and the signature algorithms only when there are any.
fn with_algorithms(extensions: String, algorithms: &str) -> String {
    if algorithms.is_empty() {
        extensions
    } else {
        format!("{extensions}_{algorithms}")
    }
}

/// The truncated SHA-256 of a JA4 part, or zeros for an empty part.
pub(crate) fn hash(part: &str) -> String {
    if part.is_empty() {
        EMPTY_HASH.to_owned()
    } else {
        sha256_12(part)
    }
}

fn find(hello: &ClientHello, kind: u16) -> Option<&Extension> {
    hello.extensions.iter().find(|e| e.kind == kind)
}

/// The highest non-GREASE `supported_versions` entry, or the legacy version without that
/// extension, as two characters; `00` when unknown.
fn version(hello: &ClientHello) -> &'static str {
    let version = match find(hello, SUPPORTED_VERSIONS) {
        Some(extension) => {
            let entries = extension
                .data
                .split_first()
                .map_or(&[][..], |(&len, rest)| {
                    rest.get(..usize::from(len)).unwrap_or(rest)
                });
            u16_values(entries)
                .filter(|&v| !is_grease(v))
                .max()
                .unwrap_or_default()
        }
        None => hello.legacy_version,
    };
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

/// Non-GREASE `signature_algorithms` entries, in the client's order.
fn signature_algorithms(hello: &ClientHello) -> Vec<u16> {
    let Some(extension) = find(hello, SIGNATURE_ALGORITHMS) else {
        return Vec::new();
    };
    let Some((len, rest)) = extension.data.split_at_checked(2) else {
        return Vec::new();
    };
    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
    non_grease(u16_values(rest.get(..len).unwrap_or(rest)))
}

fn u16_values(data: &[u8]) -> impl Iterator<Item = u16> {
    let (pairs, _) = data.as_chunks::<2>();
    pairs.iter().map(|&pair| u16::from_be_bytes(pair))
}

/// First and last character of the first ALPN value; `00` when there is none.
fn alpn(hello: &ClientHello) -> String {
    let first = find(hello, ALPN).and_then(|extension| {
        let (&len, rest) = extension.data.get(2..)?.split_first()?;
        rest.get(..usize::from(len))
    });
    match first {
        Some(value) if !value.is_empty() => alpn_ends(value),
        _ => "00".to_owned(),
    }
}

/// The value's first and last bytes as characters when both are ASCII alphanumeric, else the
/// first and last characters of its hex form.
fn alpn_ends(value: &[u8]) -> String {
    match (value.first(), value.last()) {
        (Some(&first), Some(&last))
            if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() =>
        {
            format!("{}{}", char::from(first), char::from(last))
        }
        (Some(&first), Some(&last)) => format!("{:x}{:x}", first >> 4, last & 0x0f),
        _ => "00".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ClientHello of the specification's example.
    fn spec_example() -> ClientHello {
        let ciphers = [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let kinds = [
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
            0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ];
        let algorithms: [u16; 8] = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let data = |kind: u16| -> Vec<u8> {
            match kind {
                ALPN => b"\x00\x03\x02h2".to_vec(),
                SUPPORTED_VERSIONS => vec![4, 0x0a, 0x0a, 0x03, 0x04],
                SIGNATURE_ALGORITHMS => {
                    let mut data = vec![0, 16];
                    data.extend(algorithms.iter().flat_map(|a| a.to_be_bytes()));
                    data
                }
                _ => Vec::new(),
            }
        };
        ClientHello {
            legacy_version: 0x0303,
            cipher_suites: [0x0a0a].into_iter().chain(ciphers).collect(),
            extensions: [0x2a2a]
                .into_iter()
                .chain(kinds)
                .map(|kind| Extension {
                    kind,
                    data: data(kind),
                })
                .collect(),
            ..ClientHello::default()
        }
    }

    #[test]
    fn matches_the_specification_example() {
        let ja4 = Ja4::new(&spec_example(), Transport::Tcp);
        assert_eq!(ja4.hashed(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(ja4.original(), "t13d1516h2_acb858a92679_18f69afefd3d");
        assert_eq!(
            ja4.raw(),
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
        );
        assert_eq!(
            ja4.raw_original(),
            "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_0403,0804,0401,0503,0805,0501,0806,0601"
        );
    }

    #[test]
    fn no_signature_algorithms_leaves_out_the_underscore() {
        let c = with_algorithms(
            "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01".to_owned(),
            "",
        );
        assert_eq!(hash(&c), "6d807ffa2a79");
    }

    #[test]
    fn empty_lists_hash_to_zeros() {
        let ja4 = Ja4::new(&ClientHello::default(), Transport::Quic);
        assert_eq!(ja4.hashed(), "q00i000000_000000000000_000000000000");
    }

    #[test]
    fn no_sni_is_i_and_counts_cap_at_99() {
        let mut hello = spec_example();
        hello.extensions.retain(|e| e.kind != SERVER_NAME);
        hello.cipher_suites = (1..=120).collect();
        assert!(
            Ja4::new(&hello, Transport::Tcp)
                .hashed()
                .starts_with("t13i9915h2_")
        );
    }

    #[test]
    fn alpn_ends_follow_the_specification_examples() {
        let cases: [(&[u8], &str); 10] = [
            (b"h2", "h2"),
            (b"http/1.1", "h1"),
            (b"a", "aa"),
            (&[0xab], "ab"),
            (&[0x20], "20"),
            (&[0xab, 0xcd], "ad"),
            (&[0x20, 0x61], "21"),
            (&[0x30, 0xab], "3b"),
            (&[0x61, 0x20], "60"),
            (&[0x30, 0x31, 0xab, 0xcd], "3d"),
        ];
        for (value, expected) in cases {
            assert_eq!(alpn_ends(value), expected, "ALPN {value:02x?}");
        }
        assert_eq!(alpn_ends(&[0x30, 0xab, 0xcd, 0x31]), "01");
    }
}
