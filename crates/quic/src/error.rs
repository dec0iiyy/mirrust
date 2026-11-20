use std::fmt;

/// Why a datagram could not be used to extract the ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The datagram held no long-header Initial packet.
    NoInitialPacket,
    /// A packet or frame ended before its declared length.
    Truncated,
    /// The long header names a QUIC version this crate cannot decrypt.
    UnsupportedVersion(u32),
    /// A connection ID is longer than the 20 bytes QUIC v1 and v2 allow.
    ConnectionIdTooLong(usize),
    /// An Initial packet's version or Destination Connection ID differs from the first one's.
    ConnectionChanged,
    /// Header protection could not be removed or the AEAD tag did not verify.
    Decrypt,
    /// A frame type that an Initial packet may not carry.
    UnexpectedFrame(u64),
    /// CRYPTO data reaches past the per-connection limit.
    CryptoLimitExceeded {
        /// The end offset the data or the announced message reaches.
        end: u64,
        /// [`crate::MAX_CRYPTO_LEN`].
        limit: usize,
    },
    /// A CRYPTO frame starts too far beyond the bytes received so far, which would make the
    /// assembler hold a buffer for data that may never come.
    CryptoTooFarAhead {
        /// The end offset the frame reaches.
        end: u64,
        /// The farthest end offset accepted: the received prefix plus a small slack.
        limit: usize,
    },
    /// The CRYPTO frames left too many separate gaps; no real client sends them that way.
    TooManyCryptoRanges,
    /// The CRYPTO stream starts with a handshake message other than ClientHello.
    NotClientHello(u8),
    /// CRYPTO data differs from what was received before at the same offsets. RFC 9000
    /// section 2.2 forbids that, and a receiver may keep either copy, so there is no telling
    /// which ClientHello the server's QUIC stack read.
    CryptoConflict,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInitialPacket => f.write_str("datagram holds no initial packet"),
            Self::Truncated => f.write_str("packet or frame is truncated"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported quic version {version:#010x}")
            }
            Self::ConnectionIdTooLong(len) => write!(f, "connection id of {len} bytes is too long"),
            Self::ConnectionChanged => {
                f.write_str("initial packet belongs to a different connection")
            }
            Self::Decrypt => f.write_str("initial packet does not decrypt"),
            Self::UnexpectedFrame(kind) => {
                write!(
                    f,
                    "frame type {kind:#x} is not allowed in an initial packet"
                )
            }
            Self::CryptoLimitExceeded { end, limit } => {
                write!(
                    f,
                    "crypto data up to offset {end} exceeds the {limit}-byte limit"
                )
            }
            Self::CryptoTooFarAhead { end, limit } => {
                write!(
                    f,
                    "crypto data up to offset {end} is too far ahead of the stream (limit {limit})"
                )
            }
            Self::TooManyCryptoRanges => f.write_str("crypto data arrives in too many pieces"),
            Self::NotClientHello(kind) => {
                write!(f, "handshake message type {kind} is not a client hello")
            }
            Self::CryptoConflict => {
                f.write_str("crypto data differs from an earlier copy of the same bytes")
            }
        }
    }
}

impl std::error::Error for Error {}
