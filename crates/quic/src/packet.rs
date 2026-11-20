use rustls::Side;
use rustls::quic::DirectionalKeys;

use crate::Error;
use crate::reader::Reader;

/// Longest connection ID QUIC v1 and v2 allow (RFC 9000 §17.2).
const MAX_CID_LEN: usize = 20;
/// Header form bit: set on long-header packets.
const LONG_HEADER: u8 = 0x80;
/// Packet number bytes header protection always covers; the sample starts after them (RFC 9001 §5.4.2).
const MAX_PN_LEN: usize = 4;

/// QUIC versions whose Initial packets this crate decrypts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Version {
    /// QUIC version 1 (RFC 9000), `0x00000001`.
    V1,
    /// QUIC version 2 (RFC 9369), `0x6b3343cf`.
    V2,
}

impl Version {
    /// Maps a long-header version field to a supported version.
    #[must_use]
    pub fn from_wire(version: u32) -> Option<Self> {
        match version {
            0x0000_0001 => Some(Self::V1),
            0x6b33_43cf => Some(Self::V2),
            _ => None,
        }
    }

    /// The version field as it appears on the wire.
    #[must_use]
    pub fn to_wire(self) -> u32 {
        match self {
            Self::V1 => 0x0000_0001,
            Self::V2 => 0x6b33_43cf,
        }
    }

    /// The two long-packet-type bits that mean Initial and Retry (RFC 9369 §3.2 swaps them).
    fn initial_and_retry_types(self) -> (u8, u8) {
        match self {
            Self::V1 => (0, 3),
            Self::V2 => (1, 0),
        }
    }

    fn rustls(self) -> rustls::quic::Version {
        match self {
            Self::V1 => rustls::quic::Version::V1,
            Self::V2 => rustls::quic::Version::V2,
        }
    }
}

/// One long-header packet split off a datagram, still protected.
pub(crate) struct LongPacket<'dgram> {
    pub(crate) version: Version,
    pub(crate) is_initial: bool,
    pub(crate) dcid: &'dgram [u8],
    pub(crate) scid: &'dgram [u8],
    /// Length of the address validation token; only Initial packets have the field.
    pub(crate) token_len: usize,
    /// The whole packet, header included.
    bytes: &'dgram [u8],
    /// Where the protected packet number starts within `bytes`.
    pn_offset: usize,
}

/// Splits the first packet off `datagram`.
///
/// Returns `None` when the rest of the datagram cannot hold a long-header packet whose length
/// is known: it is empty, starts with a short header (1-RTT) or a zero byte (padding), or is a
/// Retry packet.
pub(crate) fn split_long_packet(datagram: &[u8]) -> Result<Option<(LongPacket<'_>, &[u8])>, Error> {
    let mut reader = Reader::new(datagram);
    let Ok(first) = reader.u8() else {
        return Ok(None);
    };
    if first & LONG_HEADER == 0 {
        return Ok(None);
    }
    let wire_version = reader.u32()?;
    let version =
        Version::from_wire(wire_version).ok_or(Error::UnsupportedVersion(wire_version))?;
    let dcid = connection_id(&mut reader)?;
    let scid = connection_id(&mut reader)?;
    let kind = (first >> 4) & 0x03;
    let (initial, retry) = version.initial_and_retry_types();
    if kind == retry {
        return Ok(None);
    }
    let token_len = if kind == initial {
        reader.varint_bytes()?.len()
    } else {
        0
    };
    let length = usize::try_from(reader.varint()?).map_err(|_| Error::Truncated)?;
    let pn_offset = reader.position();
    let end = pn_offset.checked_add(length).ok_or(Error::Truncated)?;
    let (bytes, rest) = datagram.split_at_checked(end).ok_or(Error::Truncated)?;
    let packet = LongPacket {
        version,
        is_initial: kind == initial,
        dcid,
        scid,
        token_len,
        bytes,
        pn_offset,
    };
    Ok(Some((packet, rest)))
}

/// The Destination Connection ID of the long-header packet a datagram starts with, whatever its
/// version or type; `None` for a short header, a truncated header or a connection ID longer than
/// 20 bytes.
///
/// A UDP socket can carry several connections of one client, so the datagrams of one peer are
/// told apart by this ID.
#[must_use]
pub fn destination_connection_id(datagram: &[u8]) -> Option<&[u8]> {
    let mut reader = Reader::new(datagram);
    if reader.u8().ok()? & LONG_HEADER == 0 {
        return None;
    }
    reader.u32().ok()?;
    connection_id(&mut reader).ok()
}

fn connection_id<'dgram>(reader: &mut Reader<'dgram>) -> Result<&'dgram [u8], Error> {
    let len = usize::from(reader.u8()?);
    if len > MAX_CID_LEN {
        return Err(Error::ConnectionIdTooLong(len));
    }
    reader.bytes(len)
}

/// Derives the client's Initial keys from the Destination Connection ID of its first Initial
/// packet (RFC 9001 §5.2).
pub(crate) fn client_initial_keys(version: Version, dcid: &[u8]) -> DirectionalKeys {
    let suite = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(rustls::Tls13CipherSuite::quic_suite)
        .expect("rustls's TLS_AES_128_GCM_SHA256 is a TLS 1.3 suite with QUIC support");
    suite.keys(dcid, Side::Server, version.rustls()).remote
}

impl LongPacket<'_> {
    /// Removes header protection and decrypts the payload, returning the plaintext frames.
    pub(crate) fn decrypt(&self, keys: &DirectionalKeys) -> Result<Vec<u8>, Error> {
        let mut buf = self.bytes.to_vec();
        let pn_offset = self.pn_offset;
        let sample_start = pn_offset + MAX_PN_LEN;
        let sample = self
            .bytes
            .get(sample_start..sample_start + keys.header.sample_len())
            .ok_or(Error::Truncated)?;
        let (header, rest) = buf.split_at_mut(pn_offset);
        let first = header.first_mut().ok_or(Error::Truncated)?;
        let pn_field = rest.get_mut(..MAX_PN_LEN).ok_or(Error::Truncated)?;
        keys.header
            .decrypt_in_place(sample, first, pn_field)
            .map_err(|_| Error::Decrypt)?;
        let pn_len = usize::from(*first & 0x03) + 1;
        let packet_number = pn_field[..pn_len]
            .iter()
            .fold(0u64, |acc, &b| acc << 8 | u64::from(b));

        // The client's first flight has no acknowledged packet, so the truncated packet number
        // is the full one (RFC 9000 §A.3 with largest_pn = -1 decodes to the encoded value).
        let header_len = pn_offset + pn_len;
        let (header, payload) = buf.split_at_mut(header_len);
        let plain_len = keys
            .packet
            .decrypt_in_place(packet_number, header, payload)
            .map_err(|_| Error::Decrypt)?
            .len();
        buf.drain(..header_len);
        buf.truncate(plain_len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_connection_id_of_any_long_header() {
        // Version 0x1a2a3a4a (reserved), a 3-byte DCID, then whatever follows.
        let long = [0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 0x03, 7, 8, 9, 0x00, 0xff];
        assert_eq!(destination_connection_id(&long), Some(&[7, 8, 9][..]));
        // Short header, truncated header, truncated ID, ID over 20 bytes, empty datagram.
        assert_eq!(destination_connection_id(&[0x40, 0, 0, 0, 1, 0]), None);
        assert_eq!(destination_connection_id(&[0xc0, 0, 0, 0]), None);
        assert_eq!(destination_connection_id(&long[..8]), None);
        let mut too_long = vec![0xc0, 0, 0, 0, 1, 21];
        too_long.extend([0; 21]);
        assert_eq!(destination_connection_id(&too_long), None);
        assert_eq!(destination_connection_id(&[]), None);
    }
}
