//! A UDP socket for quinn that reads each client's QUIC Initial on its way in.
//!
//! quinn and rustls never show the ClientHello, so [`SniffingSocket`] wraps the socket quinn
//! reads from: each long-header datagram is also fed to a [`quic::InitialAssembler`] for its
//! connection (peer and Destination Connection ID), and the finished ClientHello waits in
//! [`ClientHellos`] under (peer address, original Destination Connection ID) until the
//! connection handler takes it. Datagrams reach quinn unchanged.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use quic::{ClientInitial, InitialAssembler};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

/// How long an entry is kept. A ClientHello arrives within a round trip of the first Initial
/// packet and the connection is accepted soon after, so a few seconds are enough; the shorter
/// the time, the less a flood of spoofed datagrams can hold.
const ENTRY_TTL: Duration = Duration::from_secs(5);

/// Handshakes in progress and ClientHello messages not yet taken are each capped at this many.
const MAX_ENTRIES: usize = 4096;

/// ClientHello messages read off the wire, waiting for their connection to be accepted.
#[derive(Debug, Default)]
pub(crate) struct ClientHellos {
    tables: Mutex<Tables>,
}

#[derive(Debug, Default)]
struct Tables {
    /// Per peer and Destination Connection ID, the Initial packets seen so far. A peer's
    /// connections can share one UDP socket, so the peer alone does not name a connection.
    pending: Table<(SocketAddr, Vec<u8>), InitialAssembler>,
    /// Finished Initial flights, ClientHello included, by peer and original DCID.
    complete: Table<(SocketAddr, Vec<u8>), ClientInitial>,
}

impl ClientHellos {
    /// Feeds one received datagram to the peer's assembler.
    fn observe(&self, from: SocketAddr, datagram: &[u8]) {
        self.observe_at(from, datagram, Instant::now());
    }

    fn observe_at(&self, from: SocketAddr, datagram: &[u8], now: Instant) {
        // Only a long header can start an Initial packet.
        let Some(dcid) = quic::destination_connection_id(datagram) else {
            return;
        };
        let key = (from, dcid.to_vec());
        let mut tables = self.tables.lock().expect("ClientHello table lock poisoned");
        let Tables { pending, complete } = &mut *tables;
        let finished = if let Some(assembler) = pending.get_mut(&key) {
            let finished = assembler.push(datagram).ok().flatten();
            if finished.is_some() {
                pending.remove(&key);
            }
            finished
        } else {
            // Nothing is stored for a datagram that holds no Initial packet or does not
            // decrypt: a Handshake or 0-RTT datagram, or garbage.
            let mut assembler = InitialAssembler::new();
            match assembler.push(datagram) {
                Ok(None) => {
                    pending.insert(key, assembler, now);
                    None
                }
                Ok(finished) => finished,
                Err(_) => None,
            }
        };
        if let Some(initial) = finished {
            let key = (from, initial.dcid().to_vec());
            complete.insert(key, initial, now);
        }
    }

    /// Removes and returns the Initial flight, ClientHello included, that `from` sent on the
    /// connection it opened with `dcid`.
    pub(crate) fn take(&self, from: SocketAddr, dcid: &[u8]) -> Option<ClientInitial> {
        self.tables
            .lock()
            .expect("ClientHello table lock poisoned")
            .complete
            .remove(&(from, dcid.to_vec()))
    }
}

/// A map of at most [`MAX_ENTRIES`] values that forgets the oldest first.
///
/// Anyone can fill it with valid Initial packets from spoofed addresses, so a newcomer never
/// loses to the entries already there: expired entries go first, then the oldest one.
#[derive(Debug)]
struct Table<K, V> {
    entries: HashMap<K, Entry<V>>,
    /// Keys by insertion number, oldest first.
    by_age: BTreeMap<u64, K>,
    next_number: u64,
}

#[derive(Debug)]
struct Entry<V> {
    value: V,
    inserted_at: Instant,
    /// The entry's key in [`Table::by_age`].
    number: u64,
}

impl<K, V> Default for Table<K, V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            by_age: BTreeMap::new(),
            next_number: 0,
        }
    }
}

impl<K: Eq + Hash + Clone, V> Table<K, V> {
    /// Stores `value`, replacing any entry under `key`, after dropping what has expired and,
    /// if the table is still full, the oldest entry.
    fn insert(&mut self, key: K, value: V, now: Instant) {
        self.remove(&key);
        self.drop_expired(now);
        while self.entries.len() >= MAX_ENTRIES {
            let Some((_, oldest)) = self.by_age.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        let number = self.next_number;
        self.next_number += 1;
        self.by_age.insert(number, key.clone());
        let entry = Entry {
            value,
            inserted_at: now,
            number,
        };
        self.entries.insert(key, entry);
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key).map(|entry| &mut entry.value)
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        let entry = self.entries.remove(key)?;
        self.by_age.remove(&entry.number);
        Some(entry.value)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Drops the entries at least [`ENTRY_TTL`] old, oldest first.
    fn drop_expired(&mut self, now: Instant) {
        while let Some(oldest) = self.by_age.first_entry() {
            let expired = self
                .entries
                .get(oldest.get())
                .is_none_or(|entry| now.saturating_duration_since(entry.inserted_at) >= ENTRY_TTL);
            if !expired {
                break;
            }
            self.entries.remove(&oldest.remove());
        }
    }
}

/// quinn's own UDP socket, with every received datagram also shown to [`ClientHellos`].
#[derive(Debug)]
pub(crate) struct SniffingSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    hellos: Arc<ClientHellos>,
}

impl SniffingSocket {
    pub(crate) fn new(inner: Arc<dyn AsyncUdpSocket>, hellos: Arc<ClientHellos>) -> Self {
        Self { inner, hellos }
    }
}

impl AsyncUdpSocket for SniffingSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let received = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(received)) => received,
            other => return other,
        };
        for (buf, meta) in bufs.iter().zip(meta.iter()).take(received) {
            // With GRO one buffer holds several datagrams, `stride` bytes apart.
            for datagram in buf[..meta.len].chunks(meta.stride.max(1)) {
                self.hellos.observe(meta.addr, datagram);
            }
        }
        Poll::Ready(Ok(received))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use quic::Version;
    use rustls::Side;

    use super::*;

    /// A distinct client address per `n`.
    fn peer(n: usize) -> SocketAddr {
        let n = u32::try_from(n).expect("small index");
        (Ipv4Addr::from(0x0a00_0000 + n), 40_000).into()
    }

    /// A client Initial packet carrying `frames`, sealed with the public Initial keys.
    fn initial(dcid: &[u8], frames: &[u8]) -> Vec<u8> {
        let keys = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .and_then(rustls::Tls13CipherSuite::quic_suite)
            .expect("QUIC suite")
            .keys(dcid, Side::Client, rustls::quic::Version::V1)
            .local;
        let mut header = vec![0xc3];
        header.extend(Version::V1.to_wire().to_be_bytes());
        header.push(u8::try_from(dcid.len()).expect("short dcid"));
        header.extend(dcid);
        header.extend([0, 0]); // no source connection ID, no token
        let length = u16::try_from(4 + frames.len() + 16).expect("short packet");
        header.extend((0x4000 | length).to_be_bytes());
        let pn_offset = header.len();
        header.extend(0_u32.to_be_bytes());

        let mut payload = frames.to_vec();
        let tag = keys
            .packet
            .encrypt_in_place(0, &header, &mut payload)
            .expect("seal");
        payload.extend(tag.as_ref());
        let (first, pn_field) = header.split_at_mut(pn_offset);
        keys.header
            .encrypt_in_place(&payload[..16], &mut first[0], pn_field)
            .expect("protect header");
        header.extend(payload);
        header
    }

    fn crypto_frame(offset: u16, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        frame.extend((0x4000 | offset).to_be_bytes());
        frame.extend((0x4000 | u16::try_from(data.len()).expect("short data")).to_be_bytes());
        frame.extend(data);
        frame
    }

    /// What an attacker sends: a valid Initial with one CRYPTO byte at a far offset.
    fn spoof() -> Vec<u8> {
        initial(&[9; 8], &crypto_frame(1000, b"x"))
    }

    /// A 24-byte ClientHello-shaped handshake message.
    fn hello() -> Vec<u8> {
        let mut message = vec![0x01, 0, 0, 20];
        message.extend(0..20);
        message
    }

    fn lens(hellos: &ClientHellos) -> (usize, usize) {
        let tables = hellos.tables.lock().expect("lock");
        (tables.pending.len(), tables.complete.len())
    }

    #[test]
    fn spoofed_initials_cannot_keep_a_real_client_out() {
        let hellos = ClientHellos::default();
        let now = Instant::now();
        for n in 0..MAX_ENTRIES + 100 {
            hellos.observe_at(peer(n), &spoof(), now);
        }
        assert_eq!(lens(&hellos), (MAX_ENTRIES, 0));

        let real = peer(1_000_000);
        let dcid = [7; 8];
        let message = hello();
        let first = initial(&dcid, &crypto_frame(0, &message[..10]));
        let second = initial(&dcid, &crypto_frame(10, &message[10..]));
        hellos.observe_at(real, &first, now);
        hellos.observe_at(real, &second, now);
        let found = hellos
            .take(real, &dcid)
            .expect("the real client is tracked");
        assert_eq!(found.client_hello(), message);
        assert_eq!(lens(&hellos), (MAX_ENTRIES - 1, 0));
    }

    #[test]
    fn connections_from_one_address_are_assembled_separately() {
        // One UDP socket can carry several connections; their Initial datagrams interleave.
        let hellos = ClientHellos::default();
        let now = Instant::now();
        let client = peer(1);
        let (dcid_a, dcid_b) = ([1; 8], [2; 8]);
        let (mut hello_a, mut hello_b) = (hello(), hello());
        hello_a[5] = 0xaa;
        hello_b[5] = 0xbb;
        let datagrams = [
            initial(&dcid_a, &crypto_frame(0, &hello_a[..10])),
            initial(&dcid_b, &crypto_frame(0, &hello_b[..10])),
            initial(&dcid_a, &crypto_frame(10, &hello_a[10..])),
            initial(&dcid_b, &crypto_frame(10, &hello_b[10..])),
        ];
        for datagram in &datagrams {
            hellos.observe_at(client, datagram, now);
        }
        let found_a = hellos.take(client, &dcid_a).expect("connection A is read");
        let found_b = hellos.take(client, &dcid_b).expect("connection B is read");
        assert_eq!(found_a.client_hello(), hello_a);
        assert_eq!(found_b.client_hello(), hello_b);
    }

    #[test]
    fn a_full_table_of_finished_flights_forgets_the_oldest_first() {
        let hellos = ClientHellos::default();
        let now = Instant::now();
        let dcid = [3; 8];
        let datagram = initial(&dcid, &crypto_frame(0, &hello()));
        for n in 0..=MAX_ENTRIES {
            hellos.observe_at(peer(n), &datagram, now);
        }
        assert_eq!(lens(&hellos), (0, MAX_ENTRIES));
        assert!(
            hellos.take(peer(0), &dcid).is_none(),
            "the oldest is evicted"
        );
        assert!(hellos.take(peer(1), &dcid).is_some());
        assert!(hellos.take(peer(MAX_ENTRIES), &dcid).is_some());
    }

    #[test]
    fn entries_expire_after_the_ttl() {
        let hellos = ClientHellos::default();
        let start = Instant::now();
        for n in 0..10 {
            hellos.observe_at(peer(n), &spoof(), start);
        }
        assert_eq!(lens(&hellos).0, 10);
        // Half the TTL later they all stay; the next insert after it drops them.
        hellos.observe_at(peer(10), &spoof(), start + ENTRY_TTL / 2);
        assert_eq!(lens(&hellos).0, 11);
        hellos.observe_at(peer(11), &spoof(), start + ENTRY_TTL);
        assert_eq!(lens(&hellos).0, 2);
    }

    #[test]
    fn garbage_and_non_initial_datagrams_store_nothing() {
        let hellos = ClientHellos::default();
        let now = Instant::now();
        hellos.observe_at(peer(0), &[0x40, 1, 2, 3], now);
        hellos.observe_at(peer(0), &[0xc3, 0, 0, 0, 1, 0, 0, 0, 0], now);
        hellos.observe_at(peer(0), &[], now);
        assert_eq!(lens(&hellos), (0, 0));
    }
}
