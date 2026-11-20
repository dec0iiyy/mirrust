//! Akamai HTTP/2 fingerprint (`S|WU|P|PS`) exactly as tls.peet.ws builds it.

use std::fmt::Write as _;

use md5::{Digest, Md5};

use crate::frame::ParsedFrame;

/// The Akamai fingerprint of a frame list, byte-identical to tls.peet.ws's.
///
/// Settings come from the first SETTINGS frame only, the window increment from the first
/// `WINDOW_UPDATE` on any stream (`00` when there is none), priorities from PRIORITY frames
/// (`0` when there are none), and pseudo-header order from the first HEADERS frame.
#[must_use]
pub fn akamai_fingerprint(frames: &[ParsedFrame]) -> String {
    format!(
        "{}|{}|{}|{}",
        settings(frames),
        window_update(frames),
        priorities(frames),
        header_order(frames),
    )
}

/// Lowercase hex MD5 of [`akamai_fingerprint`], as in `akamai_fingerprint_hash`.
#[must_use]
pub fn akamai_fingerprint_hash(frames: &[ParsedFrame]) -> String {
    md5_hex(&akamai_fingerprint(frames))
}

pub(crate) fn md5_hex(text: &str) -> String {
    Md5::digest(text.as_bytes())
        .iter()
        .fold(String::with_capacity(32), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

fn settings(frames: &[ParsedFrame]) -> String {
    let Some(frame) = frames.iter().find(|f| f.frame_type == "SETTINGS") else {
        return String::new();
    };
    let mut parts = Vec::with_capacity(frame.settings.len());
    for setting in &frame.settings {
        let Some((name, value)) = setting.split_once(" = ") else {
            return "error".to_owned();
        };
        let id = match name {
            "HEADER_TABLE_SIZE" => "1",
            "ENABLE_PUSH" => "2",
            "MAX_CONCURRENT_STREAMS" => "3",
            "INITIAL_WINDOW_SIZE" => "4",
            "MAX_FRAME_SIZE" => "5",
            "MAX_HEADER_LIST_SIZE" => "6",
            "ENABLE_CONNECT_PROTOCOL" => "8",
            "NO_RFC7540_PRIORITIES" => "9",
            other => match other.strip_prefix("UNKNOWN_SETTING_") {
                Some(raw) if raw.parse::<u16>().is_ok() => raw,
                _ => return "error".to_owned(),
            },
        };
        parts.push(format!("{id}:{value}"));
    }
    parts.join(";")
}

fn window_update(frames: &[ParsedFrame]) -> String {
    frames
        .iter()
        .find(|f| f.frame_type == "WINDOW_UPDATE")
        .map_or_else(|| "00".to_owned(), |f| f.increment.to_string())
}

fn priorities(frames: &[ParsedFrame]) -> String {
    let list: Vec<String> = frames
        .iter()
        .filter(|f| f.frame_type == "PRIORITY")
        .map(|f| {
            let p = f.priority.unwrap_or_default();
            format!(
                "{}:{}:{}:{}",
                f.stream_id, p.exclusive, p.depends_on, p.weight
            )
        })
        .collect();
    if list.is_empty() {
        "0".to_owned()
    } else {
        list.join(",")
    }
}

/// The byte after `:` of each pseudo-header, with a comma after it only when the header is
/// among the first three of the block (counting regular headers too).
fn header_order(frames: &[ParsedFrame]) -> String {
    let Some(frame) = frames.iter().find(|f| f.frame_type == "HEADERS") else {
        return String::new();
    };
    let mut order = String::new();
    for (index, header) in frame.headers.iter().enumerate() {
        if let [b':', letter, ..] = *header.as_bytes() {
            // Go's `string(header[1])` turns the byte into the code point of the same value.
            order.push(char::from(letter));
            if index < 3 {
                order.push(',');
            }
        }
    }
    order
}
