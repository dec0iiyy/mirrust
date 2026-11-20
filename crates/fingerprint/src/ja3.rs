use crate::{
    ClientHello,
    grease::{is_grease, is_grease_group},
    text::{join, md5_hex},
};

/// The JA3 fingerprint: `version,ciphers,extensions,groups,point_formats`, GREASE removed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ja3 {
    text: String,
    hash: String,
}

impl Ja3 {
    /// Computes JA3 from a ClientHello read with [`ClientHello::parse_peet`].
    #[must_use]
    pub fn new(hello: &ClientHello) -> Self {
        let text = format!(
            "{},{},{},{},{}",
            hello.legacy_version,
            join(non_grease_ciphers(hello), "-"),
            join(non_grease_extensions(hello), "-"),
            join(
                hello
                    .supported_groups
                    .iter()
                    .filter(|&&g| !is_grease_group(g)),
                "-"
            ),
            join(&hello.point_formats, "-"),
        );
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

pub(crate) fn non_grease_ciphers(hello: &ClientHello) -> impl Iterator<Item = u16> {
    hello
        .cipher_suites
        .iter()
        .copied()
        .filter(|&c| !is_grease(c))
}

pub(crate) fn non_grease_extensions(hello: &ClientHello) -> impl Iterator<Item = u16> {
    hello
        .extensions
        .iter()
        .map(|e| e.kind)
        .filter(|&k| !is_grease(k))
}
