//! TCP SYN fingerprints as tls.peet.ws reports them.
//!
//! [`Syn::parse`] reads one captured packet, starting at the IPv4 or IPv6 header, and gives
//! the `tcp_syn` object ([`SynDetails`]) and its p0f v3 signature. [`TcpIp`] is the
//! report's `tcpip` object built from it. Parsing only: no capture.
//!
//! Which packets yield a SYN matches tls.peet.ws exactly, including how its packet decoder (gopacket) reads them:
//! a packet gopacket cannot decode down to TCP, a fragment, a non-TCP packet, or anything but a
//! plain SYN (ACK, FIN or RST set) gives `None`. Malformed input never panics.

mod options;

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Serialize, Serializer};

use options::SynOptions;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
const PROTOCOL_TCP: u8 = 6;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_URG: u8 = 0x20;
const TCP_ECE: u8 = 0x40;
const TCP_CWR: u8 = 0x80;

/// The fields tls.peet.ws records from a client's SYN: the `tcpip.tcp_syn` object.
///
/// Serializes like tls.peet.ws: same keys, same order, `ip_id` and `df` only for
/// IPv4, `window_scale` only when the option is present, and `options` as `null` when there
/// are none (a Go nil slice).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SynDetails {
    /// 4 or 6.
    pub ip_version: u8,
    /// Source address, as Go prints it (an IPv4-mapped IPv6 address prints as IPv4).
    pub src_ip: String,
    /// Destination address, printed like `src_ip`.
    pub dst_ip: String,
    /// TCP source port.
    pub src_port: u16,
    /// TCP destination port.
    pub dst_port: u16,
    /// IPv4 TTL or IPv6 hop limit, as observed.
    pub ttl: u8,
    /// IPv4 identification; absent for IPv6.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_id: Option<u16>,
    /// IPv4 don't-fragment flag; absent for IPv6.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub df: Option<bool>,
    /// ECN in the IP header (ECT/CE bits) or any of the TCP ECE, CWR, NS flags.
    pub ecn: bool,
    /// TCP window, unscaled.
    pub window: u16,
    /// MSS option value, 0 without one.
    pub mss: u16,
    /// Window scale option value, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_scale: Option<u8>,
    /// SACK-permitted option present.
    pub sack_permitted: bool,
    /// Timestamps option present.
    pub timestamps: bool,
    /// Option names in wire order (`mss`, `nop`, `wscale`, `sackOK`, `timestamp`, `sack`,
    /// `eol`, `unknown-<kind>`), at most 24.
    #[serde(serialize_with = "null_if_empty")]
    pub options: Vec<String>,
    /// The option bytes in lowercase hex.
    pub options_raw: String,
    /// `options` joined with `,`.
    pub option_order: String,
    /// TCP payload bytes captured (TCP Fast Open data).
    pub payload_len: usize,
    /// Packet length from the IP header (IPv6: payload length + 40).
    pub packet_len: usize,
}

/// A parsed SYN: tls.peet.ws's details plus the p0f v3 signature it reports next to them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Syn {
    /// The `tcp_syn` object.
    pub details: SynDetails,
    /// p0f v3 TCP signature, `ver:ttl+?:olen:mss:wsize,scale:olayout:quirks:pclass`, with the
    /// observed TTL and the literal window (tls.peet.ws reports observations, not guesses).
    pub p0f: String,
}

impl Syn {
    /// Reads a packet captured from the IP header on. Returns `None` for anything tls.peet.ws
    /// would not fingerprint: not IPv4/IPv6 + TCP, a header gopacket rejects, a fragment, an
    /// IPv6 extension header, or a segment that is not a bare SYN.
    #[must_use]
    pub fn parse(packet: &[u8]) -> Option<Self> {
        let ip = match packet.first()? >> 4 {
            4 => IpHeader::parse_v4(packet)?,
            6 => IpHeader::parse_v6(packet)?,
            _ => return None,
        };
        let tcp = TcpHeader::parse(ip.segment)?;
        if tcp.flags & TCP_SYN == 0 || tcp.flags & (TCP_ACK | TCP_FIN | TCP_RST) != 0 {
            return None;
        }

        let options = SynOptions::parse(tcp.options);
        let ecn = ip.ecn || tcp.flags & (TCP_ECE | TCP_CWR) != 0 || tcp.ns;
        let window_scale = options.window_scale;
        let p0f = format!(
            "{}:{}+?:{}:{}:{},{}:{}:{}:{}",
            ip.version,
            ip.ttl,
            ip.option_len,
            options.mss,
            tcp.window,
            window_scale.unwrap_or(0),
            options.layout.join(","),
            quirks(&ip, &tcp, &options, ecn).join(","),
            if tcp.payload_len > 0 { "+" } else { "0" },
        );
        let is_v4 = ip.version == 4;
        let details = SynDetails {
            ip_version: ip.version,
            src_ip: go_ip_string(ip.src),
            dst_ip: go_ip_string(ip.dst),
            src_port: tcp.src_port,
            dst_port: tcp.dst_port,
            ttl: ip.ttl,
            ip_id: is_v4.then_some(ip.id),
            df: is_v4.then_some(ip.df),
            ecn,
            window: tcp.window,
            mss: options.mss,
            window_scale,
            sack_permitted: options.sack_permitted,
            timestamps: options.timestamps,
            option_order: options.names.join(","),
            options: options.names,
            options_raw: hex(tcp.options),
            payload_len: tcp.payload_len,
            packet_len: ip.packet_len,
        };
        Some(Self { details, p0f })
    }
}

/// The report's `tcpip` object.
///
/// tls.peet.ws fills `ip` and `tcp` (plus `cap_length`, ports, ...) from the client's last ACK
/// seen by a packet capture; those are not produced here, so they stay `{}`, as tls.peet.ws
/// reports them without a capture. `tcp_syn` and `p0f` are dropped when there is no SYN.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TcpIp {
    ip: EmptyObject,
    tcp: EmptyObject,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_syn: Option<SynDetails>,
    #[serde(skip_serializing_if = "String::is_empty")]
    p0f: String,
}

impl TcpIp {
    /// The object for a connection whose SYN was (or was not) captured.
    #[must_use]
    pub fn new(syn: Option<Syn>) -> Self {
        syn.map_or_else(Self::default, |syn| Self {
            tcp_syn: Some(syn.details),
            p0f: syn.p0f,
            ..Self::default()
        })
    }

    /// The SYN details, if a SYN was captured.
    #[must_use]
    pub fn tcp_syn(&self) -> Option<&SynDetails> {
        self.tcp_syn.as_ref()
    }

    /// The p0f signature, empty without a SYN.
    #[must_use]
    pub fn p0f(&self) -> &str {
        &self.p0f
    }
}

impl From<Option<Syn>> for TcpIp {
    fn from(syn: Option<Syn>) -> Self {
        Self::new(syn)
    }
}

/// A Go struct with no fields set: always `{}`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
struct EmptyObject {}

/// The IP header fields a SYN fingerprint needs, and the TCP segment it carries.
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent header flags, each a p0f quirk input"
)]
struct IpHeader<'pkt> {
    version: u8,
    src: IpAddr,
    dst: IpAddr,
    ttl: u8,
    id: u16,
    df: bool,
    ecn: bool,
    /// The reserved ("evil") bit of IPv4.
    reserved: bool,
    /// A non-zero IPv6 flow label.
    flow: bool,
    /// IPv4 option bytes (header length − 20); 0 for IPv6.
    option_len: usize,
    packet_len: usize,
    /// The IP payload, cut to the length the header declares.
    segment: &'pkt [u8],
}

impl<'pkt> IpHeader<'pkt> {
    /// Mirrors gopacket's `IPv4.DecodeFromBytes` checks, then tls.peet.ws's.
    fn parse_v4(packet: &'pkt [u8]) -> Option<Self> {
        let header: &[u8; IPV4_HEADER_LEN] = packet.first_chunk()?;
        let header_len = usize::from(header[0] & 0x0f) * 4;
        let declared = usize::from(u16::from_be_bytes([header[2], header[3]]));
        // gopacket: a zero length (TCP segmentation offload) means "the whole buffer",
        // stored back into a uint16.
        let length = if declared == 0 {
            packet.len() & 0xffff
        } else {
            declared
        };
        if length < IPV4_HEADER_LEN
            || header_len < IPV4_HEADER_LEN
            || header_len > length
            || header_len > packet.len()
        {
            return None;
        }
        let data = packet.get(..length).unwrap_or(packet);
        let (head, segment) = data.split_at(header_len);
        if !ipv4_options_valid(&head[IPV4_HEADER_LEN..]) {
            return None;
        }

        let flags = header[6] >> 5;
        let fragment_offset = u16::from_be_bytes([header[6] & 0x1f, header[7]]);
        let more_fragments = flags & 0b001 != 0;
        if more_fragments || fragment_offset != 0 || header[9] != PROTOCOL_TCP {
            return None;
        }
        let [src, dst]: [[u8; 4]; 2] = [
            [header[12], header[13], header[14], header[15]],
            [header[16], header[17], header[18], header[19]],
        ];
        Some(Self {
            version: 4,
            src: Ipv4Addr::from(src).into(),
            dst: Ipv4Addr::from(dst).into(),
            ttl: header[8],
            id: u16::from_be_bytes([header[4], header[5]]),
            df: flags & 0b010 != 0,
            ecn: header[1] & 0x03 != 0,
            reserved: flags & 0b100 != 0,
            flow: false,
            option_len: header_len - IPV4_HEADER_LEN,
            packet_len: length,
            segment,
        })
    }

    /// Mirrors gopacket's `IPv6.DecodeFromBytes`; like p0f, extension headers are not skipped,
    /// so only a TCP next header counts.
    fn parse_v6(packet: &'pkt [u8]) -> Option<Self> {
        let header: &[u8; IPV6_HEADER_LEN] = packet.first_chunk()?;
        let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
        if header[6] != PROTOCOL_TCP || length == 0 {
            return None;
        }
        let payload = &packet[IPV6_HEADER_LEN..];
        let traffic_class = (header[0] << 4) | (header[1] >> 4);
        let address = |at: usize| -> IpAddr {
            let mut bytes = [0; 16];
            bytes.copy_from_slice(&header[at..at + 16]);
            Ipv6Addr::from(bytes).into()
        };
        Some(Self {
            version: 6,
            src: address(8),
            dst: address(24),
            ttl: header[7],
            id: 0,
            df: false,
            ecn: traffic_class & 0x03 != 0,
            reserved: false,
            flow: header[1] & 0x0f != 0 || header[2] != 0 || header[3] != 0,
            option_len: 0,
            packet_len: IPV6_HEADER_LEN + length,
            segment: payload.get(..length).unwrap_or(payload),
        })
    }
}

/// gopacket rejects an IPv4 header whose options do not parse, so tls.peet.ws never sees its TCP.
fn ipv4_options_valid(mut options: &[u8]) -> bool {
    while let Some((&kind, rest)) = options.split_first() {
        match kind {
            0 => return true,
            1 => options = rest,
            _ => {
                let Some(&length) = rest.first() else {
                    return false;
                };
                let length = usize::from(length);
                if length <= 2 || length > options.len() {
                    return false;
                }
                options = &options[length..];
            }
        }
    }
    true
}

/// The TCP header fields a SYN fingerprint needs.
struct TcpHeader<'pkt> {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    ns: bool,
    window: u16,
    urgent: u16,
    /// Header bytes past the first 20.
    options: &'pkt [u8],
    payload_len: usize,
}

impl<'pkt> TcpHeader<'pkt> {
    /// Mirrors gopacket's `TCP.DecodeFromBytes` as tls.peet.ws sees it: a header longer than the
    /// segment still yields a TCP layer (its options run to the end, no payload), and option
    /// errors do not matter because tls.peet.ws rereads the raw bytes.
    fn parse(segment: &'pkt [u8]) -> Option<Self> {
        let header: &[u8; TCP_HEADER_LEN] = segment.first_chunk()?;
        let header_len = usize::from(header[12] >> 4) * 4;
        if header_len < TCP_HEADER_LEN {
            return None;
        }
        let (contents, payload) = segment.split_at(header_len.min(segment.len()));
        Some(Self {
            src_port: u16::from_be_bytes([header[0], header[1]]),
            dst_port: u16::from_be_bytes([header[2], header[3]]),
            seq: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
            ack: u32::from_be_bytes([header[8], header[9], header[10], header[11]]),
            flags: header[13],
            ns: header[12] & 0x01 != 0,
            window: u16::from_be_bytes([header[14], header[15]]),
            urgent: u16::from_be_bytes([header[18], header[19]]),
            options: &contents[TCP_HEADER_LEN..],
            payload_len: payload.len(),
        })
    }
}

/// p0f quirks in tls.peet.ws's order.
fn quirks(
    ip: &IpHeader<'_>,
    tcp: &TcpHeader<'_>,
    options: &SynOptions,
    ecn: bool,
) -> Vec<&'static str> {
    let has = |flag: u8| tcp.flags & flag != 0;
    let checks = [
        (ip.df, "df"),
        (ip.df && ip.id != 0, "id+"),
        (!ip.df && ip.version == 4 && ip.id == 0, "id-"),
        (ecn, "ecn"),
        (ip.reserved, "0+"),
        (ip.flow, "flow"),
        (tcp.seq == 0, "seq-"),
        (!has(TCP_ACK) && tcp.ack != 0 && !has(TCP_RST), "ack+"),
        (has(TCP_ACK) && tcp.ack == 0, "ack-"),
        (!has(TCP_URG) && tcp.urgent != 0, "uptr+"),
        (has(TCP_URG), "urgf+"),
        (has(TCP_PSH), "pushf+"),
        (options.zero_timestamp, "ts1-"),
        (options.nonzero_timestamp2, "ts2+"),
        (options.nonzero_eol_padding, "opt+"),
        (options.excessive_window_scale, "exws"),
        (options.bad, "bad"),
    ];
    checks
        .into_iter()
        .filter_map(|(present, quirk)| present.then_some(quirk))
        .collect()
}

/// Go's `net.IP.String`: an IPv4-mapped IPv6 address prints as plain IPv4.
fn go_ip_string(address: IpAddr) -> String {
    match address {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
        IpAddr::V4(v4) => v4.to_string(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// tls.peet.ws writes the option list as `null`, not `[]`, when there are no options.
fn null_if_empty<S: Serializer>(names: &[String], serializer: S) -> Result<S::Ok, S::Error> {
    if names.is_empty() {
        serializer.serialize_none()
    } else {
        serializer.collect_seq(names)
    }
}
