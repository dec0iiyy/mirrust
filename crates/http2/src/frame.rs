//! The frame record kept for every frame a client sends, as tls.peet.ws reports it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Serialize, Serializer};

/// One client frame as tls.peet.ws reports it under `http2.sent_frames`.
///
/// Serializes to the same JSON as Go's `types.ParsedFrame`: same keys, same order, and the
/// same `omitempty` rules (zero numbers, empty lists and absent records are left out).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ParsedFrame {
    /// Frame type name (`SETTINGS`, `HEADERS`, `UNKNOWN_FRAME_TYPE_10`, ...).
    #[serde(rename = "frame_type", skip_serializing_if = "String::is_empty")]
    pub frame_type: String,
    /// Stream identifier, reserved bit cleared.
    #[serde(rename = "stream_id", skip_serializing_if = "is_zero")]
    pub stream_id: u32,
    /// Payload length from the frame header.
    #[serde(skip_serializing_if = "is_zero")]
    pub length: u32,
    /// DATA payload without padding, base64 in JSON.
    #[serde(skip_serializing_if = "Vec::is_empty", serialize_with = "as_base64")]
    pub payload: Vec<u8>,
    /// Decoded `name: value` lines of a HEADERS frame.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<String>,
    /// `NAME = value` lines of a SETTINGS frame, in wire order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub settings: Vec<String>,
    /// `WINDOW_UPDATE` increment.
    #[serde(skip_serializing_if = "is_zero")]
    pub increment: u32,
    /// Flag names tls.peet.ws knows for this frame type, like `EndStream (0x1)`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<&'static str>,
    /// Priority of a PRIORITY frame or a HEADERS frame with the priority flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    /// Contents of a GOAWAY frame.
    #[serde(rename = "goaway", skip_serializing_if = "Option::is_none")]
    pub go_away: Option<GoAway>,
}

/// Stream priority (RFC 9113 section 5.3, deprecated but still sent by some clients).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
pub struct Priority {
    /// Wire weight plus one, so 1 to 256.
    pub weight: u16,
    /// Stream this one depends on.
    pub depends_on: u32,
    /// 1 when the exclusive bit is set, else 0.
    pub exclusive: u8,
}

/// GOAWAY contents. Go gives this struct no JSON tags, so the keys are its field names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
pub struct GoAway {
    /// Last stream the sender processed.
    #[serde(rename = "LastStreamID")]
    pub last_stream_id: u32,
    /// Error code.
    #[serde(rename = "ErrCode")]
    pub err_code: u32,
    /// Opaque debug data, base64 in JSON (`""` when empty).
    #[serde(rename = "DebugData", serialize_with = "as_base64")]
    pub debug_data: Vec<u8>,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde passes fields by reference"
)]
fn is_zero(value: &u32) -> bool {
    *value == 0
}

fn as_base64<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&STANDARD.encode(bytes))
}
