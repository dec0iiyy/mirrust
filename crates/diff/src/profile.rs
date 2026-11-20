//! A ClientHello reduced to what stays the same across connections of one client build.

use std::{collections::BTreeMap, fmt};

use fingerprint::{ClientHello, Extension, Ja3, Ja4, Ja4Peet, PeetPrint, Transport, is_grease};
use serde_json::{Value, json};

use crate::http2::Akamai;

const SERVER_NAME: u16 = 0;
const SIGNATURE_ALGORITHMS: u16 = 13;
const ALPN: u16 = 16;
const RECORD_SIZE_LIMIT: u16 = 28;
const SUPPORTED_VERSIONS: u16 = 43;
/// `application_settings` with Chrome's old codepoint (Chrome up to 132).
pub const ALPS_OLD: u16 = 17_513;
/// `application_settings` with the new codepoint (Chrome 133 and later).
pub const ALPS: u16 = 17_613;
/// `encrypted_client_hello`.
pub const ECH: u16 = 0xfe0d;
/// TLS 1.3, what a server negotiates when the client offers it.
const TLS13: u16 = 0x0304;

/// The parts of a client fingerprint that [`crate::compare`] looks at.
///
/// GREASE, the client random, the session id, key share bytes, the padding length and the
/// SNI value are dropped here, so two connections of one client build give equal values.
/// Extensions keep the client's order; [`crate::Options::strict_order`] decides whether it
/// counts.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Profile {
    /// `legacy_version` of the ClientHello.
    pub legacy_version: u16,
    /// `supported_versions` entries.
    pub versions: Vec<u16>,
    /// Cipher suites in the client's order.
    pub ciphers: Vec<u16>,
    /// Extension types in the client's order.
    pub extensions: Vec<u16>,
    /// `supported_groups` entries.
    pub groups: Vec<u16>,
    /// Groups the client sent a key share for.
    pub key_share_groups: Vec<u16>,
    /// `signature_algorithms` entries in the client's order.
    pub signature_algorithms: Vec<u16>,
    /// ALPN protocol names.
    pub alpn: Vec<String>,
    /// `ec_point_formats` entries.
    pub point_formats: Vec<u8>,
    /// The `psk_key_exchange_modes` entry (tls.peet.ws reports only the first).
    pub psk_mode: Option<u8>,
    /// `compress_certificate` algorithms.
    pub cert_compression: Vec<u16>,
    /// `record_size_limit` value.
    pub record_size_limit: Option<u16>,
    /// Protocols in the ALPS extension, whichever codepoint it uses.
    pub alps_protocols: Vec<String>,
    /// The HTTP/2 Akamai fingerprint, when the input had one.
    pub http2: Option<Akamai>,
    pub(crate) names: Names,
}

/// Display names that the input carried, by id.
#[derive(Debug, Clone, Default)]
pub(crate) struct Names {
    pub(crate) ciphers: BTreeMap<u16, String>,
    pub(crate) extensions: BTreeMap<u16, String>,
    pub(crate) groups: BTreeMap<u16, String>,
    pub(crate) signatures: BTreeMap<u16, String>,
}

/// Why an input could not be read as a fingerprint.
#[derive(Debug)]
#[non_exhaustive]
pub enum InputError {
    /// The input is empty.
    Empty,
    /// The input looks like JSON but does not parse.
    Json(serde_json::Error),
    /// The input is neither JSON nor hex.
    Hex,
    /// The bytes are not a ClientHello handshake message.
    NotClientHello,
    /// A field tls.peet.ws always sends is missing.
    Missing(&'static str),
    /// A field has a value that cannot be read.
    Malformed {
        /// The field.
        field: &'static str,
        /// What it held.
        value: String,
    },
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty input"),
            Self::Json(error) => write!(f, "invalid JSON: {error}"),
            Self::Hex => f.write_str("input is neither JSON nor hex"),
            Self::NotClientHello => f.write_str("bytes are not a ClientHello handshake message"),
            Self::Missing(field) => write!(f, "missing field `{field}`"),
            Self::Malformed { field, value } => write!(f, "malformed `{field}`: {value:?}"),
        }
    }
}

impl std::error::Error for InputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for InputError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl Profile {
    /// Reads either input form: tls.peet.ws JSON (`/api/all`, `/api/tls`, or the bare `tls`
    /// object), a `{"hex": …}` corpus line, or a ClientHello as hex.
    ///
    /// Hex may be the handshake message (starting with `01`) or a TLS record (starting with
    /// `16 03`, whose 5-byte header is stripped); whitespace, `:` and a leading `0x` are
    /// ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`InputError`] when the text is neither form or misses required fields.
    pub fn parse(text: &str) -> Result<Self, InputError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(InputError::Empty);
        }
        if text.starts_with('{') {
            let value: Value = serde_json::from_str(text)?;
            return match value.get("hex").and_then(Value::as_str) {
                Some(hex) if value.get("tls").is_none() => Self::from_hex(hex),
                _ => Self::from_json(&value),
            };
        }
        Self::from_hex(text)
    }

    /// Reads a ClientHello written as hex; see [`Self::parse`] for the accepted forms.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::Hex`] for text that is not hex and
    /// [`InputError::NotClientHello`] for bytes that are not a ClientHello.
    pub fn from_hex(text: &str) -> Result<Self, InputError> {
        let digits: String = text
            .trim()
            .trim_start_matches("0x")
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ':')
            .collect();
        let bytes = decode_hex(&digits).ok_or(InputError::Hex)?;
        Self::from_bytes(&bytes)
    }

    /// Reads a ClientHello handshake message, or a TLS record holding one.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::NotClientHello`] when the bytes do not start a ClientHello.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InputError> {
        let message = match bytes {
            [0x16, 0x03, _, _, _, rest @ ..] => rest,
            _ => bytes,
        };
        let hello = ClientHello::parse_peet(message);
        if message.first() != Some(&1) || hello.cipher_suites.is_empty() {
            return Err(InputError::NotClientHello);
        }
        Self::from_json(&json!({ "tls": peet_tls(&hello) }))
    }

    /// Reads tls.peet.ws JSON: a response with a `tls` (and maybe `http2`) object, or a bare
    /// `tls` object.
    ///
    /// # Errors
    ///
    /// Returns an [`InputError`] when `ja3` or `peetprint` is missing or malformed.
    pub fn from_json(value: &Value) -> Result<Self, InputError> {
        let tls = value
            .get("tls")
            .filter(|tls| tls.is_object())
            .unwrap_or(value);
        let ja3 = str_field(tls, "ja3")?;
        let peetprint = str_field(tls, "peetprint")?;
        let [version, ciphers, extensions, groups, point_formats] = split_n(ja3, ',', "ja3")?;
        let [versions, _, _, signatures, _, cert_compression, _, _] =
            split_n(peetprint, '|', "peetprint")?;

        let mut profile = Self {
            legacy_version: version.parse().map_err(|_| malformed("ja3", ja3))?,
            versions: numbers(versions, '-', "peetprint")?,
            ciphers: numbers(ciphers, '-', "ja3")?,
            extensions: numbers(extensions, '-', "ja3")?,
            groups: numbers(groups, '-', "ja3")?,
            signature_algorithms: numbers(signatures, '-', "peetprint")?,
            point_formats: numbers(point_formats, '-', "ja3")?,
            cert_compression: numbers(cert_compression, '-', "peetprint")?,
            ..Self::default()
        };
        profile.read_details(tls);
        profile.http2 = value
            .get("http2")
            .and_then(|http2| http2.get("akamai_fingerprint"))
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(Akamai::parse)
            .transpose()?;
        Ok(profile)
    }

    /// Reads what only the readable `ciphers` and `extensions` details carry.
    fn read_details(&mut self, tls: &Value) {
        let readable_ciphers = tls
            .get("ciphers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|name| !name.starts_with("TLS_GREASE"));
        for (&id, name) in self.ciphers.iter().zip(readable_ciphers) {
            self.names.ciphers.insert(id, name.to_owned());
        }

        let details: Vec<&Value> = tls
            .get("extensions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|detail| !str_or_empty(detail, "name").starts_with("TLS_GREASE"))
            .collect();
        let mut signature_names = Vec::new();
        let extensions = self.extensions.clone();
        for (&id, detail) in extensions.iter().zip(details) {
            self.names
                .extensions
                .insert(id, str_or_empty(detail, "name").to_owned());
            match id {
                SIGNATURE_ALGORITHMS | 50 | 53 => {
                    signature_names.extend(strings(detail, "signature_algorithms"));
                }
                10 => {
                    for name in strings(detail, "supported_groups") {
                        if let Some(group) = id_in_name(&name).filter(|&g| !is_grease(g)) {
                            self.names.groups.insert(group, name);
                        }
                    }
                }
                ALPN => self.alpn = strings(detail, "protocols"),
                ALPS | ALPS_OLD => self.alps_protocols = strings(detail, "protocols"),
                RECORD_SIZE_LIMIT => {
                    self.record_size_limit =
                        decode_hex(str_or_empty(detail, "data")).and_then(|bytes| {
                            Some(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?))
                        });
                }
                45 => {
                    self.psk_mode = id_in_name(str_or_empty(detail, "PSK_Key_Exchange_Mode"))
                        .and_then(|mode| u8::try_from(mode).ok());
                }
                51 => {
                    self.key_share_groups = detail
                        .get("shared_keys")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_object)
                        .flat_map(|share| share.keys())
                        .filter_map(|name| id_in_name(name))
                        .filter(|&group| !is_grease(group))
                        .collect();
                }
                _ => {}
            }
        }
        if signature_names.len() == self.signature_algorithms.len() {
            for (&id, name) in self.signature_algorithms.iter().zip(signature_names) {
                self.names.signatures.insert(id, name);
            }
        }
    }

    /// Whether the client offers encrypted client hello (or its GREASE).
    #[must_use]
    pub fn ech(&self) -> bool {
        self.extensions.contains(&ECH)
    }

    /// The ALPS extension codepoint the client uses, if any.
    #[must_use]
    pub fn alps(&self) -> Option<u16> {
        self.extensions
            .iter()
            .copied()
            .find(|&id| id == ALPS || id == ALPS_OLD)
    }

    /// JA4 per the FoxIO spec, computed from this profile.
    ///
    /// The SNI value and the extension data JA4 does not read are not kept, so the profile is
    /// written back into a ClientHello with placeholder data first.
    #[must_use]
    pub fn ja4(&self) -> Ja4 {
        let extensions = self
            .extensions
            .iter()
            .map(|&kind| Extension {
                kind,
                data: match kind {
                    SERVER_NAME => b"\x00\x05\x00\x00\x02xx".to_vec(),
                    SUPPORTED_VERSIONS => with_len8(&be_bytes(&self.versions)),
                    SIGNATURE_ALGORITHMS => with_len16(&be_bytes(&self.signature_algorithms)),
                    ALPN => with_len16(
                        &self
                            .alpn
                            .iter()
                            .flat_map(|name| with_len8(name.as_bytes()))
                            .collect::<Vec<u8>>(),
                    ),
                    _ => Vec::new(),
                },
            })
            .collect();
        let mut hello = ClientHello::default();
        hello.legacy_version = self.legacy_version;
        hello.cipher_suites.clone_from(&self.ciphers);
        hello.extensions = extensions;
        hello.supported_versions.clone_from(&self.versions);
        hello
            .signature_algorithms
            .clone_from(&self.signature_algorithms);
        hello.alpn = self
            .alpn
            .iter()
            .map(|name| name.as_bytes().to_vec())
            .collect();
        Ja4::new(&hello, Transport::Tcp)
    }
}

/// The `tls` object tls.peet.ws reports for a ClientHello read with
/// [`ClientHello::parse_peet`].
#[must_use]
pub fn peet_tls(hello: &ClientHello) -> Value {
    let negotiated = if hello.supported_versions.contains(&TLS13) {
        TLS13
    } else {
        hello.legacy_version
    };
    let ja3 = Ja3::new(hello);
    let ja4 = Ja4Peet::new(hello, negotiated, Transport::Tcp);
    let peetprint = PeetPrint::new(hello);
    json!({
        "ciphers": hello.readable_ciphers(),
        "extensions": hello.extension_details(),
        "tls_version_record": hello.legacy_version.to_string(),
        "tls_version_negotiated": negotiated.to_string(),
        "ja3": ja3.text(),
        "ja3_hash": ja3.hash(),
        "ja4": ja4.hashed(),
        "ja4_r": ja4.raw(),
        "peetprint": peetprint.text(),
        "peetprint_hash": peetprint.hash(),
    })
}

fn str_field<'v>(value: &'v Value, field: &'static str) -> Result<&'v str, InputError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(InputError::Missing(field))
}

fn str_or_empty<'v>(value: &'v Value, field: &str) -> &'v str {
    value.get(field).and_then(Value::as_str).unwrap_or_default()
}

/// A string array field; `null` (Go's nil slice) reads as empty.
fn strings(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn malformed(field: &'static str, value: &str) -> InputError {
    InputError::Malformed {
        field,
        value: value.to_owned(),
    }
}

fn split_n<'t, const N: usize>(
    text: &'t str,
    separator: char,
    field: &'static str,
) -> Result<[&'t str; N], InputError> {
    let parts: Vec<&str> = text.split(separator).collect();
    parts.try_into().map_err(|_| malformed(field, text))
}

/// A `-`-separated list of decimal numbers, `GREASE` entries and GREASE values dropped.
fn numbers<T>(text: &str, separator: char, field: &'static str) -> Result<Vec<T>, InputError>
where
    T: std::str::FromStr + Copy + Into<u16>,
{
    text.split(separator)
        .filter(|item| !item.is_empty() && *item != "GREASE")
        .map(|item| item.parse::<T>().map_err(|_| malformed(field, text)))
        .filter(|item| {
            item.as_ref()
                .map_or(true, |&value| !is_grease(value.into()))
        })
        .collect()
}

/// The id in a tls.peet.ws name: `X25519 (29)`, `TLS_GREASE (0x0a0a)`, `Unknown curve 1234`.
fn id_in_name(name: &str) -> Option<u16> {
    let inner = match name.strip_suffix(')') {
        Some(head) => &head[head.rfind('(')? + 1..],
        None => name.rsplit(' ').next()?,
    };
    match inner.strip_prefix("0x") {
        Some(hex) => u16::from_str_radix(hex, 16).ok(),
        None => inner.parse().ok(),
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

fn be_bytes(values: &[u16]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

fn with_len8(data: &[u8]) -> Vec<u8> {
    let len = u8::try_from(data.len()).unwrap_or(u8::MAX);
    [&[len][..], data].concat()
}

fn with_len16(data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(data.len()).unwrap_or(u16::MAX);
    [&len.to_be_bytes()[..], data].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_ids_in_names() {
        assert_eq!(id_in_name("X25519MLKEM768 (4588)"), Some(4588));
        assert_eq!(id_in_name("TLS_GREASE (0x6a6a)"), Some(0x6a6a));
        assert_eq!(id_in_name("Unknown curve 1234"), Some(1234));
        assert_eq!(
            id_in_name("PSK with (EC)DHE key establishment (psk_dhe_ke) (1)"),
            Some(1)
        );
    }
}
