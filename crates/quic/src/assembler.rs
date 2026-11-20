use std::fmt;
use std::ops::Range;

use rustls::quic::DirectionalKeys;

use crate::packet::{self, Version};
use crate::{Error, frame};

/// Most CRYPTO stream bytes kept per connection.
///
/// A post-quantum Chrome ClientHello is about 1.8 KB and even one with ECH, many extensions and a
/// resumption ticket stays well under 8 KB, so 16 KiB leaves a wide margin. Initial keys are
/// public, so anyone can send a valid Initial; every byte allowed here is memory a spoofed
/// datagram can make the server hold, and raising it raises that.
pub const MAX_CRYPTO_LEN: usize = 16 * 1024;

/// Most separate byte ranges the CRYPTO stream may hold at once.
///
/// A real client's ClientHello arrives in a few frames, in order or nearly so, and leaves at
/// most a handful of gaps; a datagram of one-byte frames with gaps between them can make
/// hundreds. Past this many the packet is treated as hostile and rejected.
const MAX_CRYPTO_RANGES: usize = 64;

/// How far past the contiguous prefix of the CRYPTO stream a frame may reach.
///
/// Frames of a real ClientHello arrive within a packet or two of their offset, even when a
/// datagram is reordered (a ClientHello fills two or three 1200-byte packets); 4 KiB covers that.
/// The buffer never grows past the received prefix plus this, so one spoofed frame at a far
/// offset costs a few KiB rather than the whole [`MAX_CRYPTO_LEN`].
const CRYPTO_SLACK: usize = 4 * 1024;

/// TLS handshake message type of ClientHello.
const CLIENT_HELLO: u8 = 0x01;
/// Handshake message header: one type byte and a 24-bit length.
const HANDSHAKE_HEADER_LEN: usize = 4;

/// Most datagram sizes kept per connection.
///
/// A ClientHello takes one to three datagrams; the cap bounds what a client that keeps sending
/// Initial packets without finishing its ClientHello can make the server hold.
pub const MAX_DATAGRAM_SIZES: usize = 32;

/// The ClientHello of a QUIC connection and the Initial packet fields it came with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInitial {
    version: Version,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    token_len: usize,
    datagram_sizes: Vec<usize>,
    client_hello: Vec<u8>,
}

impl ClientInitial {
    /// The QUIC version of the client's Initial packets.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// The Destination Connection ID the client chose; the Initial keys derive from it.
    #[must_use]
    pub fn dcid(&self) -> &[u8] {
        &self.dcid
    }

    /// The client's Source Connection ID.
    #[must_use]
    pub fn scid(&self) -> &[u8] {
        &self.scid
    }

    /// Length of the address validation token in the client's first Initial packet; 0 when it
    /// sent none (RFC 9000 §17.2.2).
    #[must_use]
    pub fn token_len(&self) -> usize {
        self.token_len
    }

    /// UDP payload sizes of the datagrams whose Initial packets were read, in arrival order,
    /// up to and including the one that completed the ClientHello; at most
    /// [`MAX_DATAGRAM_SIZES`] are kept.
    ///
    /// A datagram counts whole, with any coalesced packets and padding after its Initial
    /// packets.
    #[must_use]
    pub fn datagram_sizes(&self) -> &[usize] {
        &self.datagram_sizes
    }

    /// The handshake message from its type byte `0x01`, the input of
    /// `fingerprint::ClientHello::parse`.
    #[must_use]
    pub fn client_hello(&self) -> &[u8] {
        &self.client_hello
    }

    /// Takes the handshake message out.
    #[must_use]
    pub fn into_client_hello(self) -> Vec<u8> {
        self.client_hello
    }
}

/// Collects a client's Initial packets until its ClientHello is complete.
///
/// Feed it every datagram the client sends before the server answers. The first Initial packet
/// fixes the version and Destination Connection ID, and later Initial packets must match them.
/// CRYPTO frames may arrive in any order, across packets and datagrams, and may repeat. If
/// a repeat has other bytes than the first copy, the assembler gives up for good
/// ([`Error::CryptoConflict`]): the server's QUIC stack may have kept either copy, and a
/// ClientHello that it did not read must not be reported.
/// Memory stays under [`MAX_CRYPTO_LEN`] plus one datagram, and while the start of the stream is
/// missing, under a few KiB.
#[derive(Default)]
pub struct InitialAssembler {
    connection: Option<Connection>,
    crypto: CryptoStream,
    datagram_sizes: Vec<usize>,
    complete: bool,
    /// Two copies of the same CRYPTO bytes differed; every later `push` fails.
    conflict: bool,
}

struct Connection {
    version: Version,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    token_len: usize,
    keys: DirectionalKeys,
}

impl fmt::Debug for InitialAssembler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialAssembler")
            .field("version", &self.connection.as_ref().map(|c| c.version))
            .field("dcid", &self.connection.as_ref().map(|c| &c.dcid))
            .field("received", &self.crypto.ranges)
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

impl InitialAssembler {
    /// Creates an assembler that has seen no packets.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether [`push`](Self::push) has already returned the ClientHello.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Processes one UDP datagram from the client.
    ///
    /// Every long-header packet in the datagram is visited; Initial packets are decrypted and
    /// their CRYPTO frames stored, 0-RTT and Handshake packets are skipped, and a short-header
    /// packet ends the datagram. Returns the ClientHello once every byte up to its length has
    /// arrived, exactly once; after that it returns `Ok(None)` without reading the datagram.
    ///
    /// # Errors
    ///
    /// Returns an error when the datagram holds no Initial packet, a packet is malformed or does
    /// not decrypt, an Initial packet belongs to another connection, a frame is not allowed in
    /// an Initial packet, the CRYPTO stream does not start with a ClientHello, the data exceeds
    /// [`MAX_CRYPTO_LEN`], a CRYPTO frame starts far beyond the bytes received so far, or the
    /// stream is in too many separate pieces. CRYPTO data from packets before the failing one
    /// is kept, and when an Initial packet of the datagram was read before the failing packet,
    /// the datagram counts and there is no error: a QUIC stack, too, handles the packets in
    /// front of a malformed one and drops the rest.
    ///
    /// [`Error::CryptoConflict`] when CRYPTO data differs from an earlier copy of the same
    /// bytes; every later call then returns it again.
    pub fn push(&mut self, datagram: &[u8]) -> Result<Option<ClientInitial>, Error> {
        if self.conflict {
            return Err(Error::CryptoConflict);
        }
        if self.complete {
            return Ok(None);
        }
        let mut rest = datagram;
        let mut read_initial = false;
        loop {
            match self.push_packet(&mut rest) {
                Ok(Some(PacketKind::Initial)) => read_initial = true,
                Ok(Some(PacketKind::Other)) => {}
                Ok(None) => break,
                Err(Error::CryptoConflict) => {
                    self.conflict = true;
                    self.crypto = CryptoStream::default();
                    return Err(Error::CryptoConflict);
                }
                Err(_) if read_initial => break,
                Err(error) => return Err(error),
            }
        }
        if !read_initial {
            return Err(Error::NoInitialPacket);
        }
        if self.datagram_sizes.len() < MAX_DATAGRAM_SIZES {
            self.datagram_sizes.push(datagram.len());
        }
        self.finish()
    }

    /// Reads the long-header packet at the start of `rest` and moves `rest` past it; `None`
    /// at the end of the datagram. An Initial packet's CRYPTO frames are stored.
    fn push_packet(&mut self, rest: &mut &[u8]) -> Result<Option<PacketKind>, Error> {
        let Some((packet, next)) = packet::split_long_packet(rest)? else {
            return Ok(None);
        };
        *rest = next;
        if !packet.is_initial {
            return Ok(Some(PacketKind::Other));
        }
        let connection = self.connection.get_or_insert_with(|| Connection {
            version: packet.version,
            dcid: packet.dcid.to_vec(),
            scid: packet.scid.to_vec(),
            token_len: packet.token_len,
            keys: packet::client_initial_keys(packet.version, packet.dcid),
        });
        if connection.version != packet.version || connection.dcid != packet.dcid {
            return Err(Error::ConnectionChanged);
        }
        let payload = packet.decrypt(&connection.keys)?;
        for crypto in frame::crypto_frames(&payload)? {
            self.crypto.insert(crypto.offset, crypto.data)?;
        }
        Ok(Some(PacketKind::Initial))
    }

    fn finish(&mut self) -> Result<Option<ClientInitial>, Error> {
        let Some(message_len) = self.crypto.message_len()? else {
            return Ok(None);
        };
        let Some(connection) = &self.connection else {
            return Ok(None);
        };
        if self.crypto.contiguous_len() < message_len {
            return Ok(None);
        }
        self.complete = true;
        let mut client_hello = std::mem::take(&mut self.crypto.data);
        client_hello.truncate(message_len);
        Ok(Some(ClientInitial {
            version: connection.version,
            dcid: connection.dcid.clone(),
            scid: connection.scid.clone(),
            token_len: connection.token_len,
            datagram_sizes: std::mem::take(&mut self.datagram_sizes),
            client_hello,
        }))
    }
}

/// What [`InitialAssembler::push_packet`] read.
enum PacketKind {
    Initial,
    /// 0-RTT or Handshake, which are skipped.
    Other,
}

/// The client's Initial-level CRYPTO stream, filled in by offset.
#[derive(Debug, Default)]
struct CryptoStream {
    data: Vec<u8>,
    /// Received byte ranges, sorted and merged.
    ranges: Vec<Range<usize>>,
}

impl CryptoStream {
    fn insert(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Error> {
        let too_long = |end: u64| Error::CryptoLimitExceeded {
            end,
            limit: MAX_CRYPTO_LEN,
        };
        let end = u64::try_from(bytes.len())
            .ok()
            .and_then(|len| offset.checked_add(len))
            .ok_or_else(|| too_long(u64::MAX))?;
        let range = usize::try_from(offset)
            .ok()
            .zip(usize::try_from(end).ok())
            .filter(|&(_, end)| end <= MAX_CRYPTO_LEN)
            .map(|(start, end)| start..end)
            .ok_or_else(|| too_long(end))?;
        if range.is_empty() {
            return Ok(());
        }
        let reach = self.contiguous_len() + CRYPTO_SLACK;
        if range.end > reach {
            return Err(Error::CryptoTooFarAhead { end, limit: reach });
        }
        // The stored ranges that overlap or touch `range` are `first..last`; the list is
        // sorted and merged, so two binary searches find them.
        let first = self.ranges.partition_point(|r| r.end < range.start);
        let last = self.ranges.partition_point(|r| r.start <= range.end);
        // A retransmission repeats the bytes (RFC 9000 section 2.2). Anything else is not
        // taken: which copy a receiver keeps is its own business.
        for held in &self.ranges[first..last] {
            let both = range.start.max(held.start)..range.end.min(held.end);
            if both.start < both.end
                && self.data[both.clone()]
                    != bytes[both.start - range.start..both.end - range.start]
            {
                return Err(Error::CryptoConflict);
            }
        }
        if first == last && self.ranges.len() >= MAX_CRYPTO_RANGES {
            return Err(Error::TooManyCryptoRanges);
        }
        if let Some(missing) = range.end.checked_sub(self.data.len()) {
            self.data.reserve_exact(missing);
            self.data.resize(range.end, 0);
        }
        self.data[range.clone()].copy_from_slice(bytes);
        if first == last {
            self.ranges.insert(first, range);
        } else {
            let start = range.start.min(self.ranges[first].start);
            let end = range.end.max(self.ranges[last - 1].end);
            self.ranges[first] = start..end;
            self.ranges.drain(first + 1..last);
        }
        Ok(())
    }

    /// Length of the prefix received without gaps.
    fn contiguous_len(&self) -> usize {
        self.ranges
            .first()
            .filter(|r| r.start == 0)
            .map_or(0, |r| r.end)
    }

    /// Length of the first handshake message, header included, once its header has arrived.
    fn message_len(&self) -> Result<Option<usize>, Error> {
        if self.contiguous_len() < HANDSHAKE_HEADER_LEN {
            return Ok(None);
        }
        let [kind, len @ ..] = [self.data[0], self.data[1], self.data[2], self.data[3]];
        if kind != CLIENT_HELLO {
            return Err(Error::NotClientHello(kind));
        }
        let body_len = len.iter().fold(0usize, |acc, &b| acc << 8 | usize::from(b));
        let message_len = HANDSHAKE_HEADER_LEN + body_len;
        if message_len > MAX_CRYPTO_LEN {
            return Err(Error::CryptoLimitExceeded {
                end: message_len as u64,
                limit: MAX_CRYPTO_LEN,
            });
        }
        Ok(Some(message_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_stream_reassembles_out_of_order_and_overlapping_data() {
        let mut stream = CryptoStream::default();
        stream.insert(6, b"world").expect("in bounds");
        assert_eq!(stream.contiguous_len(), 0);
        stream.insert(0, b"hel").expect("in bounds");
        assert_eq!(stream.contiguous_len(), 3);
        stream.insert(2, b"llo ").expect("in bounds");
        assert_eq!(stream.contiguous_len(), 11);
        assert_eq!(stream.data, b"hello world");
        assert_eq!(stream.ranges, vec![Range { start: 0, end: 11 }]);
    }

    #[test]
    fn crypto_stream_refuses_other_bytes_for_what_it_has() {
        let mut stream = CryptoStream::default();
        stream.insert(0, b"hello").expect("in bounds");
        stream.insert(8, b"rld").expect("in bounds");
        // The same bytes again, whole or in part, and new bytes next to them.
        stream.insert(0, b"hello").expect("a retransmission");
        stream
            .insert(3, b"lo wo")
            .expect("the gap, with both ends repeated");
        assert_eq!(stream.data, b"hello world");
        assert_eq!(stream.insert(4, b"O"), Err(Error::CryptoConflict));
        assert_eq!(stream.insert(9, b"lD!"), Err(Error::CryptoConflict));
        assert_eq!(
            stream.data, b"hello world",
            "nothing of a refused frame is kept"
        );
        stream.insert(11, b"!").expect("new bytes are still taken");
    }

    #[test]
    fn crypto_stream_enforces_the_limit() {
        let mut stream = CryptoStream::default();
        assert!(matches!(
            stream.insert(MAX_CRYPTO_LEN as u64, b"x"),
            Err(Error::CryptoLimitExceeded { .. })
        ));
        assert!(matches!(
            stream.insert(u64::MAX, b"x"),
            Err(Error::CryptoLimitExceeded { .. })
        ));
        stream
            .insert(0, &[0x01, 0xff, 0xff, 0xff])
            .expect("in bounds");
        assert!(matches!(
            stream.message_len(),
            Err(Error::CryptoLimitExceeded { .. })
        ));
    }

    #[test]
    fn crypto_stream_does_not_allocate_far_beyond_the_received_prefix() {
        let mut stream = CryptoStream::default();
        assert!(matches!(
            stream.insert(MAX_CRYPTO_LEN as u64 - 1, b"x"),
            Err(Error::CryptoTooFarAhead { .. })
        ));
        assert!(matches!(
            stream.insert(CRYPTO_SLACK as u64, b"x"),
            Err(Error::CryptoTooFarAhead { .. })
        ));
        assert_eq!(stream.data.capacity(), 0);
        stream
            .insert(CRYPTO_SLACK as u64 - 1, b"x")
            .expect("within the slack");
        assert!(stream.data.capacity() <= CRYPTO_SLACK + 64);
        // Filling the start moves the limit forward.
        stream.insert(0, &[0; 1000]).expect("in bounds");
        stream.insert(1000, &[0; 3000]).expect("in bounds");
        stream
            .insert(CRYPTO_SLACK as u64 + 100, b"x")
            .expect("within the slack of the longer prefix");
    }

    #[test]
    fn crypto_stream_ranges_match_a_byte_by_byte_model() {
        // A deterministic pseudo-random walk over small inserts, checked against a bitmap.
        let mut stream = CryptoStream::default();
        let mut seen = [false; 600];
        let mut state = 0x2545_f491_u32;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize
        };
        for _ in 0..400 {
            let start = next() % 580;
            let len = 1 + next() % 12;
            let result = stream.insert(start as u64, &vec![1; len]);
            if result.is_ok() {
                seen[start..start + len].fill(true);
            }
            let expected: Vec<Range<usize>> = (0..seen.len())
                .filter(|&i| seen[i] && (i == 0 || !seen[i - 1]))
                .map(|i| i..i + seen[i..].iter().take_while(|&&on| on).count())
                .collect();
            assert_eq!(stream.ranges, expected, "after inserting {start}+{len}");
            assert!(stream.ranges.len() <= MAX_CRYPTO_RANGES);
        }
    }

    #[test]
    fn crypto_stream_caps_the_number_of_ranges() {
        let mut stream = CryptoStream::default();
        for i in 0..MAX_CRYPTO_RANGES as u64 {
            stream.insert(2 * i + 1, b"x").expect("below the cap");
        }
        assert_eq!(
            stream.insert(2 * MAX_CRYPTO_RANGES as u64 + 1, b"x"),
            Err(Error::TooManyCryptoRanges)
        );
        // A frame that joins existing ranges is still fine, and the rejected one left no data.
        stream.insert(2, b"y").expect("merges two ranges");
        assert_eq!(stream.ranges.len(), MAX_CRYPTO_RANGES - 1);
        assert_eq!(stream.data.len(), 2 * MAX_CRYPTO_RANGES);
    }

    #[test]
    fn crypto_stream_rejects_other_handshake_messages() {
        let mut stream = CryptoStream::default();
        stream
            .insert(0, &[0x02, 0x00, 0x00, 0x01])
            .expect("in bounds");
        assert_eq!(stream.message_len(), Err(Error::NotClientHello(2)));
    }
}
