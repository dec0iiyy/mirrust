//! What an HTTP/3 client shows before its first request: the SETTINGS frame on its control
//! stream and the types of the unidirectional streams it opens (RFC 9114 §6.2, §7.2.4).
//!
//! The crate takes the first bytes of each stream and does no I/O. [`Http3Details::new`] builds
//! the `http3` object of a report, fingerprint included.
//!
//! # Examples
//!
//! ```
//! // Stream 2: control stream with SETTINGS { QPACK_MAX_TABLE_CAPACITY = 0 }; stream 6: QPACK
//! // encoder stream.
//! let details = http3::Http3Details::new([(2, &[0x00, 0x04, 0x02, 0x01, 0x00][..]), (6, &[0x02])]);
//! assert_eq!(details.fingerprint, "1:0|0,2");
//! ```

use std::fmt::Write as _;

use md5::{Digest, Md5};
use serde::Serialize;

/// Stream type of the control stream.
const CONTROL_STREAM: u64 = 0x00;
/// Frame type of SETTINGS.
const SETTINGS_FRAME: u64 = 0x04;

/// One setting of the client's SETTINGS frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Setting {
    /// The setting identifier.
    pub id: u64,
    /// The registered name, `GREASE` for a reserved identifier, else `UNKNOWN_<id>`.
    pub name: String,
    /// The value.
    pub value: u64,
}

/// One unidirectional stream the client opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct UniStream {
    /// The QUIC stream id (2, 6, 10, … for a client).
    pub id: u64,
    /// The stream type: the varint the stream starts with.
    #[serde(rename = "type")]
    pub kind: u64,
    /// `control`, `push`, `qpack_encoder`, `qpack_decoder`, `GREASE`, else `UNKNOWN_<type>`.
    pub name: String,
}

/// The `http3` object of a report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Http3Details {
    /// `settings|stream types`; see [`Http3Details::new`].
    pub fingerprint: String,
    /// Lowercase hex MD5 of `fingerprint`.
    pub fingerprint_hash: String,
    /// The SETTINGS frame that opens the control stream, in wire order; `None` (JSON `null`)
    /// when it was not seen.
    pub settings: Option<Vec<Setting>>,
    /// The unidirectional streams whose type was read, by stream id.
    pub streams: Vec<UniStream>,
}

impl Http3Details {
    /// Builds the details from `(stream id, first bytes)` of each unidirectional stream the
    /// client opened.
    ///
    /// A stream whose bytes do not hold a whole type varint is left out. The settings come from
    /// the first control stream. The fingerprint is `S|U`: `S` is each setting as `id:value`,
    /// joined with `;`, and `U` each stream type, joined with `,`, both in decimal with
    /// `GREASE` in place of a reserved setting (value included) or stream type.
    #[must_use]
    pub fn new<'bytes>(streams: impl IntoIterator<Item = (u64, &'bytes [u8])>) -> Self {
        let mut opened: Vec<(u64, u64, &[u8])> = streams
            .into_iter()
            .filter_map(|(id, bytes)| varint(bytes).map(|(kind, rest)| (id, kind, rest)))
            .collect();
        opened.sort_unstable_by_key(|&(id, ..)| id);
        let settings = opened
            .iter()
            .find(|&&(_, kind, _)| kind == CONTROL_STREAM)
            .and_then(|&(.., frames)| settings_frame(frames));
        let streams: Vec<UniStream> = opened
            .iter()
            .map(|&(id, kind, _)| UniStream {
                id,
                kind,
                name: stream_name(kind),
            })
            .collect();

        let setting_parts: Vec<String> = settings
            .iter()
            .flatten()
            .map(|setting| {
                if is_reserved(setting.id) {
                    "GREASE".to_owned()
                } else {
                    format!("{}:{}", setting.id, setting.value)
                }
            })
            .collect();
        let stream_parts: Vec<String> = streams
            .iter()
            .map(|stream| {
                if is_reserved(stream.kind) {
                    "GREASE".to_owned()
                } else {
                    stream.kind.to_string()
                }
            })
            .collect();
        let fingerprint = format!("{}|{}", setting_parts.join(";"), stream_parts.join(","));
        Self {
            fingerprint_hash: md5_hex(&fingerprint),
            fingerprint,
            settings,
            streams,
        }
    }
}

/// Whether `stream`, the first bytes of a unidirectional stream, is a control stream whose
/// SETTINGS frame has arrived in full.
#[must_use]
pub fn has_settings(stream: &[u8]) -> bool {
    matches!(varint(stream), Some((CONTROL_STREAM, frames)) if settings_frame(frames).is_some())
}

/// Whether `id` has the form `0x1f * N + 0x21`, reserved for settings, frame types and stream
/// types that a peer must ignore (RFC 9114 §6.2.3, §7.2.4.1, §7.2.8).
#[must_use]
pub const fn is_reserved(id: u64) -> bool {
    id >= 0x21 && id % 0x1f == 0x21 % 0x1f
}

/// The settings of the SETTINGS frame `frames` starts with; `None` when the first frame is
/// another one or has not arrived in full.
fn settings_frame(frames: &[u8]) -> Option<Vec<Setting>> {
    let (kind, rest) = varint(frames)?;
    if kind != SETTINGS_FRAME {
        return None;
    }
    let (len, rest) = varint(rest)?;
    let mut payload = rest.get(..usize::try_from(len).ok()?)?;
    let mut settings = Vec::new();
    // A payload that ends inside a pair keeps the pairs before it.
    while let Some((id, value, next)) = pair(payload) {
        payload = next;
        settings.push(Setting {
            id,
            name: setting_name(id),
            value,
        });
    }
    Some(settings)
}

fn pair(payload: &[u8]) -> Option<(u64, u64, &[u8])> {
    let (id, rest) = varint(payload)?;
    let (value, rest) = varint(rest)?;
    Some((id, value, rest))
}

fn setting_name(id: u64) -> String {
    let name = match id {
        0x01 => "SETTINGS_QPACK_MAX_TABLE_CAPACITY",
        0x06 => "SETTINGS_MAX_FIELD_SECTION_SIZE",
        0x07 => "SETTINGS_QPACK_BLOCKED_STREAMS",
        // RFC 9220.
        0x08 => "SETTINGS_ENABLE_CONNECT_PROTOCOL",
        // RFC 9297.
        0x33 => "SETTINGS_H3_DATAGRAM",
        // draft-ietf-masque-h3-datagram-04, still sent by Chrome next to 0x33.
        0x00ff_d277 => "SETTINGS_H3_DATAGRAM_DRAFT04",
        // draft-ietf-webtrans-http3.
        0x2b60_3742 => "SETTINGS_ENABLE_WEBTRANSPORT",
        0xc671_706a => "SETTINGS_WEBTRANSPORT_MAX_SESSIONS",
        id if is_reserved(id) => "GREASE",
        id => return format!("UNKNOWN_{id}"),
    };
    name.to_owned()
}

fn stream_name(kind: u64) -> String {
    let name = match kind {
        CONTROL_STREAM => "control",
        0x01 => "push",
        0x02 => "qpack_encoder",
        0x03 => "qpack_decoder",
        kind if is_reserved(kind) => "GREASE",
        kind => return format!("UNKNOWN_{kind}"),
    };
    name.to_owned()
}

/// Reads one variable-length integer (RFC 9000 §16) off the front of `data`.
fn varint(data: &[u8]) -> Option<(u64, &[u8])> {
    let (&first, rest) = data.split_first()?;
    let (tail, rest) = rest.split_at_checked((1 << (first >> 6)) - 1)?;
    let value = tail
        .iter()
        .fold(u64::from(first & 0x3f), |acc, &b| acc << 8 | u64::from(b));
    Some((value, rest))
}

fn md5_hex(text: &str) -> String {
    Md5::digest(text.as_bytes())
        .iter()
        .fold(String::with_capacity(32), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Control stream: SETTINGS { 1 = 65536, 6 = 262144, 7 = 100, 0x33 = 1, reserved 0x40 = 20 },
    /// the settings Chrome sends, then the start of another frame.
    const CONTROL: &[u8] = &[
        0x00, 0x04, 0x12, 0x01, 0x80, 0x01, 0x00, 0x00, 0x06, 0x80, 0x04, 0x00, 0x00, 0x07, 0x40,
        0x64, 0x33, 0x01, 0x40, 0x40, 0x14, 0x07,
    ];

    #[test]
    fn settings_and_streams_in_wire_order_with_grease() {
        // Streams given out of order; 0x21 + 0x1f * 2 = 0x5f is a reserved stream type.
        let streams: [(u64, &[u8]); 4] = [
            (10, &[0x03]),
            (2, CONTROL),
            (14, &[0x40, 0x5f, 0x00]),
            (6, &[0x02]),
        ];
        let details = Http3Details::new(streams);
        assert_eq!(
            details.fingerprint,
            "1:65536;6:262144;7:100;51:1;GREASE|0,2,3,GREASE"
        );
        assert_eq!(details.fingerprint_hash, md5_hex(&details.fingerprint));
        assert_eq!(details.fingerprint_hash.len(), 32);
        assert_eq!(
            serde_json::to_value(&details).expect("serializes")["settings"],
            json!([
                { "id": 1, "name": "SETTINGS_QPACK_MAX_TABLE_CAPACITY", "value": 65536 },
                { "id": 6, "name": "SETTINGS_MAX_FIELD_SECTION_SIZE", "value": 262_144 },
                { "id": 7, "name": "SETTINGS_QPACK_BLOCKED_STREAMS", "value": 100 },
                { "id": 51, "name": "SETTINGS_H3_DATAGRAM", "value": 1 },
                { "id": 64, "name": "GREASE", "value": 20 },
            ])
        );
        assert_eq!(
            serde_json::to_value(&details.streams).expect("serializes"),
            json!([
                { "id": 2, "type": 0, "name": "control" },
                { "id": 6, "type": 2, "name": "qpack_encoder" },
                { "id": 10, "type": 3, "name": "qpack_decoder" },
                { "id": 14, "type": 95, "name": "GREASE" },
            ])
        );
    }

    #[test]
    fn every_prefix_of_a_control_stream_is_handled() {
        // The SETTINGS frame ends 21 bytes in.
        for len in 0..=CONTROL.len() {
            let prefix = &CONTROL[..len];
            assert_eq!(has_settings(prefix), len >= 21, "prefix of {len} bytes");
            let details = Http3Details::new([(2, prefix)]);
            assert_eq!(
                details.settings.is_some(),
                len >= 21,
                "prefix of {len} bytes"
            );
            assert_eq!(details.streams.len(), usize::from(len >= 1));
        }
    }

    #[test]
    fn no_streams_and_other_first_frames_give_no_settings() {
        let none = Http3Details::new([]);
        assert_eq!(none.fingerprint, "|");
        assert_eq!(none.settings, None);
        // A control stream that starts with GOAWAY (0x07).
        let goaway = Http3Details::new([(2, &[0x00, 0x07, 0x01, 0x00][..])]);
        assert_eq!(goaway.settings, None);
        assert_eq!(goaway.fingerprint, "|0");
        // An empty SETTINGS frame is seen, and empty.
        let empty = Http3Details::new([(2, &[0x00, 0x04, 0x00][..])]);
        assert_eq!(empty.settings, Some(Vec::new()));
        assert!(!has_settings(&[0x02, 0x04, 0x00]));
    }

    #[test]
    fn reserved_ids_are_0x1f_n_plus_0x21() {
        let reserved: Vec<u64> = (0..=0x7f).filter(|&id| is_reserved(id)).collect();
        assert_eq!(reserved, [0x21, 0x40, 0x5f, 0x7e]);
    }
}
