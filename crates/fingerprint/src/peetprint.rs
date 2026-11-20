use crate::{
    ClientHello,
    grease::{is_grease, is_grease_group},
    text::{GreaseOr, join, md5_hex},
};

/// PeetPrint, the TLS fingerprint tls.peet.ws defines:
/// `versions|protocols|groups|signature_algorithms|psk_mode|cert_compression|ciphers|extensions`,
/// with GREASE written as `GREASE` and the extensions sorted as strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeetPrint {
    text: String,
    hash: String,
}

impl PeetPrint {
    /// Computes PeetPrint from a ClientHello read with [`ClientHello::parse_peet`].
    #[must_use]
    pub fn new(hello: &ClientHello) -> Self {
        let mut extensions: Vec<String> = hello
            .extensions
            .iter()
            .map(|e| grease_or(e.kind, is_grease(e.kind)).to_string())
            .collect();
        // Chrome shuffles its extensions, so the order is dropped; `GREASE` sorts last.
        extensions.sort_unstable();

        let text = [
            join(
                hello
                    .supported_versions
                    .iter()
                    .map(|&v| grease_or(v, is_grease(v))),
                "-",
            ),
            protocols(hello).join("-"),
            join(
                hello
                    .supported_groups
                    .iter()
                    .map(|&g| grease_or(g, is_grease_group(g))),
                "-",
            ),
            join(
                hello
                    .signature_algorithms
                    .iter()
                    .map(|&s| grease_or(s, is_grease(s))),
                "-",
            ),
            hello.psk_key_exchange_mode.unwrap_or(0).to_string(),
            join(&hello.cert_compression_algorithms, "-"),
            join(
                hello
                    .cipher_suites
                    .iter()
                    .map(|&c| grease_or(c, is_grease(c))),
                "-",
            ),
            extensions.join("-"),
        ]
        .join("|");
        let hash = md5_hex(&text);
        Self { text, hash }
    }

    /// The fingerprint string.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// MD5 of [`Self::text`], lowercase hex.
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.hash
    }
}

fn grease_or(value: u16, grease: bool) -> GreaseOr {
    GreaseOr { value, grease }
}

/// ALPN names PeetPrint knows, in the client's order: `2`, `1.1` and `1.0`; others are dropped.
pub(crate) fn protocols(hello: &ClientHello) -> Vec<&'static str> {
    hello
        .alpn
        .iter()
        // Go lowercases with Unicode rules; no non-ASCII letter lowercases into these names.
        .filter_map(|name| match name.to_ascii_lowercase().as_slice() {
            b"h2" => Some("2"),
            b"http/1.1" => Some("1.1"),
            b"http/1.0" => Some("1.0"),
            _ => None,
        })
        .collect()
}
