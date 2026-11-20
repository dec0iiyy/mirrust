//! String helpers shared by the fingerprints.

use std::fmt::{Display, Write};

use md5::Md5;
use sha2::{Digest, Sha256};

/// Joins the items' `Display` forms with `sep`, like Go's `strings.Join`.
pub(crate) fn join<I>(items: I, sep: &str) -> String
where
    I: IntoIterator,
    I::Item: Display,
{
    let mut out = String::new();
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            out.push_str(sep);
        }
        write!(out, "{item}").expect("writing to a String cannot fail");
    }
    out
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// `bytes` as Go's `encoding/json` prints a `string(bytes)`: every byte of invalid UTF-8
/// becomes its own U+FFFD.
pub(crate) fn go_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        out.extend(chunk.invalid().iter().map(|_| char::REPLACEMENT_CHARACTER));
    }
    out
}

/// MD5 of `text` as lowercase hex, as JA3 and PeetPrint hash their strings.
pub(crate) fn md5_hex(text: &str) -> String {
    hex(&Md5::digest(text.as_bytes()))
}

/// First 12 hex digits of the SHA-256 of `text`, as JA4 hashes its parts.
pub(crate) fn sha256_12(text: &str) -> String {
    let mut digest = hex(&Sha256::digest(text.as_bytes()));
    digest.truncate(12);
    digest
}

/// A value printed as `GREASE` when the predicate says so, else in decimal.
pub(crate) struct GreaseOr {
    pub(crate) value: u16,
    pub(crate) grease: bool,
}

impl Display for GreaseOr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.grease {
            f.write_str("GREASE")
        } else {
            write!(f, "{}", self.value)
        }
    }
}
