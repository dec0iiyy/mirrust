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
///
/// The byte is the one the client sent ([`ParsedFrame::second_bytes`]). For a frame without
/// them it is the second byte of the line's text, which is the same unless the client's byte
/// was not UTF-8 and became U+FFFD in the text.
fn header_order(frames: &[ParsedFrame]) -> String {
    let Some(frame) = frames.iter().find(|f| f.frame_type == "HEADERS") else {
        return String::new();
    };
    let mut order = String::new();
    for (index, header) in frame.headers.iter().enumerate() {
        if let [b':', in_text, ..] = *header.as_bytes() {
            let letter = frame.second_bytes.get(index).copied().unwrap_or(in_text);
            // Go's `string(header[1])` turns the byte into the code point of the same value.
            order.push(char::from(letter));
            if index < 3 {
                order.push(',');
            }
        }
    }
    order
}

#[cfg(test)]
mod tests {
    use crate::parser::{PREFACE, Parser, Status};

    use super::*;

    /// One HEADERS frame on stream 1 with `END_STREAM | END_HEADERS` and this header block.
    fn request(block: &[u8]) -> Vec<u8> {
        let mut bytes = PREFACE.to_vec();
        bytes.extend([
            0,
            0,
            u8::try_from(block.len()).expect("short"),
            0x1,
            0x5,
            0,
            0,
            0,
            1,
        ]);
        bytes.extend(block);
        bytes
    }

    #[test]
    fn a_pseudo_header_byte_that_is_not_utf8_is_the_byte_the_client_sent() {
        // Literal fields without indexing: the names `:` 0xff and `:m`, each with value `x`.
        let block = [
            0x00, 0x02, b':', 0xff, 0x01, b'x', 0x00, 0x02, b':', b'm', 0x01, b'x',
        ];
        let mut parser = Parser::new();
        assert_eq!(parser.feed(&request(&block)), Ok(Status::Complete));
        let frames = parser.frames();
        assert_eq!(
            frames[0].headers,
            [":\u{fffd}: x", ":m: x"],
            "the text has U+FFFD"
        );
        // tls.peet.ws has Go's `string(header[1])`: the code point with the byte's value,
        // U+00FF for 0xff. The second byte of the text is 0xef, the first of U+FFFD's three.
        assert_eq!(akamai_fingerprint(frames), "|00|0|\u{ff},m,");
    }

    #[test]
    fn frames_without_the_sent_bytes_use_the_text() {
        let frame = ParsedFrame {
            frame_type: "HEADERS".to_owned(),
            headers: vec![":method: GET".to_owned(), "accept: */*".to_owned()],
            ..ParsedFrame::default()
        };
        assert_eq!(akamai_fingerprint(&[frame]), "|00|0|m,");
    }
}
