//! A lenient ClientHello parser that reads truncated input instead of rejecting it.

/// Handshake type of a ClientHello.
const CLIENT_HELLO: u8 = 1;
/// Legacy versions [`ClientHello::parse_peet`] reads past the header: TLS 1.2 and TLS 1.3.
const PEET_LEGACY_VERSIONS: [u16; 2] = [0x0303, 0x0304];

pub(crate) const SUPPORTED_GROUPS: u16 = 0x000a;
pub(crate) const EC_POINT_FORMATS: u16 = 0x000b;
pub(crate) const SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub(crate) const ALPN: u16 = 0x0010;
pub(crate) const COMPRESS_CERTIFICATE: u16 = 0x001b;
pub(crate) const SUPPORTED_VERSIONS: u16 = 0x002b;
pub(crate) const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
/// tls.peet.ws reads extension 53 as `signature_algorithms_cert` (whose id is really 50) and
/// adds its entries to the signature algorithms; we match it for comparability.
pub(crate) const PEET_SIGNATURE_ALGORITHMS_CERT: u16 = 0x0035;

/// One extension as sent: its type and raw data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extension {
    /// Extension type.
    pub kind: u16,
    /// Extension data, without the type and length.
    pub data: Vec<u8>,
}

/// A parsed ClientHello handshake message.
///
/// Fields that the message is too short to hold are left empty;
/// GREASE values are kept as sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientHello {
    /// Handshake message length from the header.
    pub length: u32,
    /// `legacy_version`; 0x0303 in every TLS 1.3 client.
    pub legacy_version: u16,
    /// The 32-byte client random.
    pub random: Vec<u8>,
    /// Legacy session id.
    pub session_id: Vec<u8>,
    /// Cipher suites in the client's order.
    pub cipher_suites: Vec<u16>,
    /// Compression methods.
    pub compression_methods: Vec<u8>,
    /// Every extension in the client's order.
    pub extensions: Vec<Extension>,
    /// `supported_groups` entries.
    pub supported_groups: Vec<u16>,
    /// `ec_point_formats` entries.
    pub point_formats: Vec<u8>,
    /// `signature_algorithms` entries (and extension 53's, which tls.peet.ws reads as
    /// `signature_algorithms_cert`).
    pub signature_algorithms: Vec<u16>,
    /// ALPN protocol names as sent, not necessarily UTF-8.
    pub alpn: Vec<Vec<u8>>,
    /// `supported_versions` entries.
    pub supported_versions: Vec<u16>,
    /// First `psk_key_exchange_modes` entry of the last such extension with one.
    pub psk_key_exchange_mode: Option<u8>,
    /// `compress_certificate` algorithms.
    pub cert_compression_algorithms: Vec<u16>,
}

impl ClientHello {
    /// Parses a ClientHello handshake message, starting at the handshake type byte.
    ///
    /// Never fails: a message that is not a ClientHello yields an empty value, and a
    /// truncated field is left empty. Use this for [`crate::Ja4`].
    #[must_use]
    pub fn parse(message: &[u8]) -> Self {
        Self::parse_with(message, Dialect::Spec)
    }

    /// Parses like [`Self::parse`], but as tls.peet.ws does: a message whose legacy version is
    /// not TLS 1.2 or 1.3 keeps only the header. Use this for the fingerprints and details
    /// tls.peet.ws reports.
    #[must_use]
    pub fn parse_peet(message: &[u8]) -> Self {
        Self::parse_with(message, Dialect::Peet)
    }

    fn parse_with(message: &[u8], dialect: Dialect) -> Self {
        let mut hello = Self::default();
        let mut r = Reader::new(message);
        if r.u8() != Some(CLIENT_HELLO) {
            return hello;
        }
        hello.length = r.u24().unwrap_or_default();
        hello.legacy_version = r.u16().unwrap_or_default();
        if dialect == Dialect::Peet && !PEET_LEGACY_VERSIONS.contains(&hello.legacy_version) {
            return hello;
        }
        hello.random = r.bytes(32).unwrap_or_default().to_vec();
        hello.session_id = r.vec8().unwrap_or_default().to_vec();
        hello.cipher_suites = r
            .vec16()
            .map(|data| u16s(data).collect())
            .unwrap_or_default();
        hello.compression_methods = r.vec8().unwrap_or_default().to_vec();
        let extensions = r.vec16().map(extension_list).unwrap_or_default();
        for extension in &extensions {
            hello.read_extension(extension.kind, &extension.data);
        }
        hello.extensions = extensions;
        hello
    }

    fn read_extension(&mut self, kind: u16, data: &[u8]) {
        match kind {
            SUPPORTED_GROUPS => self.supported_groups.extend(len16_list(data)),
            EC_POINT_FORMATS => self.point_formats.extend(data.get(1..).unwrap_or_default()),
            SIGNATURE_ALGORITHMS | PEET_SIGNATURE_ALGORITHMS_CERT => {
                self.signature_algorithms.extend(len16_list(data));
            }
            ALPN => self
                .alpn
                .extend(alpn_names(data).into_iter().map(<[u8]>::to_vec)),
            COMPRESS_CERTIFICATE => self.cert_compression_algorithms.extend(len8_list(data)),
            SUPPORTED_VERSIONS => self.supported_versions.extend(len8_list(data)),
            PSK_KEY_EXCHANGE_MODES => {
                if let [_, mode, ..] = data {
                    self.psk_key_exchange_mode = Some(*mode);
                }
            }
            _ => {}
        }
    }
}

/// How strictly the legacy version is checked before the body is read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    /// Any legacy version: the body is always read.
    Spec,
    /// As tls.peet.ws: only TLS 1.2 and 1.3 get past the header.
    Peet,
}

/// Reads big-endian fields; a read that does not fit returns `None` and consumes nothing.
struct Reader<'msg> {
    rest: &'msg [u8],
}

impl<'msg> Reader<'msg> {
    fn new(data: &'msg [u8]) -> Self {
        Self { rest: data }
    }

    fn bytes(&mut self, n: usize) -> Option<&'msg [u8]> {
        let (head, tail) = self.rest.split_at_checked(n)?;
        self.rest = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<u32> {
        self.bytes(3)
            .map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    /// A vector with a one-byte length. The length byte stays consumed when the
    /// body is cut short.
    fn vec8(&mut self) -> Option<&'msg [u8]> {
        let n = self.u8()?;
        self.bytes(usize::from(n))
    }

    /// A vector with a two-byte length, consumed like [`Self::vec8`].
    fn vec16(&mut self) -> Option<&'msg [u8]> {
        let n = self.u16()?;
        self.bytes(usize::from(n))
    }
}

/// Big-endian `u16`s; a trailing odd byte is ignored.
pub(crate) fn u16s(data: &[u8]) -> impl Iterator<Item = u16> {
    let (pairs, _) = data.as_chunks::<2>();
    pairs.iter().map(|&pair| u16::from_be_bytes(pair))
}

/// Extensions until the block ends or an extension claims more data than is left.
fn extension_list(block: &[u8]) -> Vec<Extension> {
    let mut r = Reader::new(block);
    let mut extensions = Vec::new();
    while r.rest.len() >= 4 {
        let (Some(kind), Some(len)) = (r.u16(), r.u16()) else {
            break;
        };
        let Some(data) = r.bytes(usize::from(len)) else {
            break;
        };
        extensions.push(Extension {
            kind,
            data: data.to_vec(),
        });
    }
    extensions
}

/// A `u16` list behind a two-byte length: at most `length / 2` entries, cut at the data.
pub(crate) fn len16_list(data: &[u8]) -> impl Iterator<Item = u16> {
    let (len, rest) = data
        .split_first_chunk::<2>()
        .map_or((0, &[][..]), |(len, rest)| (u16::from_be_bytes(*len), rest));
    u16s(rest).take(usize::from(len / 2))
}

/// A `u16` list behind a one-byte length in bytes: tls.peet.ws reads entries while
/// `2 * read < length`, which is `ceil(length / 2)` entries, cut at the data.
pub(crate) fn len8_list(data: &[u8]) -> impl Iterator<Item = u16> {
    let (len, rest) = data
        .split_first()
        .map_or((0, &[][..]), |(&len, rest)| (len, rest));
    u16s(rest).take(usize::from(len).div_ceil(2))
}

/// ALPN names as raw bytes. tls.peet.ws starts a new name only while its offset is at most the
/// list length, so an empty name at the very end is dropped; a name cut short ends the list.
pub(crate) fn alpn_names(data: &[u8]) -> Vec<&[u8]> {
    let Some(&[hi, lo]) = data.get(..2) else {
        return Vec::new();
    };
    let list_len = usize::from(u16::from_be_bytes([hi, lo]));
    let mut names = Vec::new();
    let mut offset = 2;
    while offset <= list_len {
        let Some(&len) = data.get(offset) else { break };
        offset += 1;
        let Some(name) = data.get(offset..offset + usize::from(len)) else {
            break;
        };
        offset += name.len();
        names.push(name);
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_a_client_hello_is_empty() {
        assert_eq!(ClientHello::parse(&[2, 0, 0, 0]), ClientHello::default());
        assert_eq!(ClientHello::parse(&[]), ClientHello::default());
    }

    #[test]
    fn peet_keeps_only_the_header_of_tls_1_0() {
        let message = [&[1, 0, 0, 38, 3, 1][..], &[0xaa; 32], &[0]].concat();
        let hello = ClientHello::parse_peet(&message);
        assert_eq!(hello.length, 38);
        assert_eq!(hello.legacy_version, 0x0301);
        assert_eq!(hello.random, b"");
        assert_eq!(ClientHello::parse(&message).random, [0xaa; 32]);
    }

    #[test]
    fn alpn_reads_names_in_order() {
        let data = b"\x00\x0c\x02h2\x08http/1.1";
        assert_eq!(alpn_names(data), [&b"h2"[..], b"http/1.1"]);
    }

    #[test]
    fn len8_list_rounds_an_odd_length_up() {
        let versions: Vec<u16> = len8_list(&[3, 0x03, 0x04, 0x03, 0x03]).collect();
        assert_eq!(versions, [0x0304, 0x0303]);
    }
}
