//! Readable cipher suites and per-extension details: the `ciphers` and `extensions` fields
//! of tls.peet.ws's JSON, with the same names, shapes and quirks.
//!
//! Go marshals an empty slice that was never appended to as `null`, so every empty list
//! below is `null`, not `[]`.

use serde_json::{Map, Value, json};

use crate::client_hello::{
    ALPN, COMPRESS_CERTIFICATE, ClientHello, EC_POINT_FORMATS, Extension,
    PEET_SIGNATURE_ALGORITHMS_CERT, PSK_KEY_EXCHANGE_MODES, SIGNATURE_ALGORITHMS, SUPPORTED_GROUPS,
    SUPPORTED_VERSIONS, alpn_names, len8_list, len16_list, u16s,
};
use crate::grease::is_grease;
use crate::names;
use crate::text::{go_string, hex};
use crate::transport_parameters::transport_parameters;

const SERVER_NAME: u16 = 0x0000;
const STATUS_REQUEST: u16 = 0x0005;
const STATUS_REQUEST_V2: u16 = 0x0011;
const SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
const PADDING: u16 = 0x0015;
const EXTENDED_MASTER_SECRET: u16 = 0x0017;
const DELEGATED_CREDENTIALS: u16 = 0x0022;
const KEY_SHARE: u16 = 0x0033;
const QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
/// The codepoint QUIC drafts used for `quic_transport_parameters` before RFC 9001.
const QUIC_TRANSPORT_PARAMETERS_DRAFT: u16 = 0xffa5;
const APPLICATION_SETTINGS_OLD: u16 = 0x4469;
const APPLICATION_SETTINGS: u16 = 0x44cd;

impl ClientHello {
    /// Cipher suite names in the client's order, as tls.peet.ws prints them.
    ///
    /// An unnamed suite prints as `0x00FF`, a GREASE one as `TLS_GREASE (0x0A0A)`.
    #[must_use]
    pub fn readable_ciphers(&self) -> Vec<String> {
        self.cipher_suites
            .iter()
            .map(|&id| match names::cipher_suite(id) {
                Some(name) => name.to_owned(),
                None if is_grease(id) => format!("TLS_GREASE (0x{id:04X})"),
                None => format!("0x{id:04X}"),
            })
            .collect()
    }

    /// One JSON object per extension, in the client's order, as tls.peet.ws reports them;
    /// `null` when there are none.
    ///
    /// Malformed `key_share` and `application_settings` lists stop at the first entry that
    /// does not fit.
    #[must_use]
    pub fn extension_details(&self) -> Value {
        if self.extensions.is_empty() {
            return Value::Null;
        }
        self.extensions.iter().map(details).collect()
    }
}

fn details(extension: &Extension) -> Value {
    let Extension { kind, data } = extension;
    let data = data.as_slice();
    match *kind {
        SERVER_NAME => json!({
            "name": "server_name (0)",
            "server_name": data.get(5..).map(go_string).unwrap_or_default(),
        }),
        STATUS_REQUEST => status_request("status_request (5)", data),
        STATUS_REQUEST_V2 => status_request("status_request_v2 (17)", data),
        SUPPORTED_GROUPS => json!({
            "name": "supported_groups (10)",
            "supported_groups": list(len16_list(data).map(group_name)),
        }),
        EC_POINT_FORMATS => json!({
            "name": "ec_point_formats (11)",
            "elliptic_curves_point_formats": list(
                data.get(1..)
                    .unwrap_or_default()
                    .iter()
                    .map(|format| format!("0x{format:02x}")),
            ),
        }),
        SIGNATURE_ALGORITHMS | PEET_SIGNATURE_ALGORITHMS_CERT => json!({
            "name": if *kind == SIGNATURE_ALGORITHMS {
                "signature_algorithms (13)"
            } else {
                "signature_algorithms_cert (50)"
            },
            "signature_algorithms": list(len16_list(data).map(signature_name)),
        }),
        ALPN => json!({
            "name": "application_layer_protocol_negotiation (16)",
            "protocols": list(alpn_names(data).into_iter().map(go_string)),
        }),
        SIGNED_CERTIFICATE_TIMESTAMP => json!({ "name": "signed_certificate_timestamp (18)" }),
        // tls.peet.ws counts the hex digits, not the bytes.
        PADDING => json!({ "name": "padding (21)", "padding_data_length": 2 * data.len() }),
        // `extended_master_secret` has no data; tls.peet.ws reports anything past two bytes.
        EXTENDED_MASTER_SECRET => json!({
            "name": "extended_master_secret (23)",
            "master_secret_data": data.get(2..).map(hex).unwrap_or_default(),
            "extended_master_secret_data": "",
        }),
        COMPRESS_CERTIFICATE => json!({
            "name": "compress_certificate (27)",
            "algorithms": list(len8_list(data).map(|algorithm| match algorithm {
                1 => "zlib (1)".to_owned(),
                2 => "brotli (2)".to_owned(),
                3 => "zstd (3)".to_owned(),
                other => format!("{other:04x}"),
            })),
        }),
        DELEGATED_CREDENTIALS => json!({
            "name": "delegated_credentials (34)",
            "signature_hash_algorithms": list(
                delegated_credentials(data).into_iter().map(signature_name),
            ),
        }),
        SUPPORTED_VERSIONS => json!({
            "name": "supported_versions (43)",
            "versions": list(len8_list(data).map(version_name)),
        }),
        PSK_KEY_EXCHANGE_MODES => json!({
            "name": "psk_key_exchange_modes (45)",
            "PSK_Key_Exchange_Mode": match data {
                [_, 0, ..] => "PSK-only key establishment (psk) (0)",
                [_, 1, ..] => "PSK with (EC)DHE key establishment (psk_dhe_ke) (1)",
                _ => "",
            },
        }),
        KEY_SHARE => json!({ "name": "key_share (51)", "shared_keys": list(key_shares(data)) }),
        // tls.peet.ws reports `name` and `data`; `parameters` is mirrust's own.
        QUIC_TRANSPORT_PARAMETERS | QUIC_TRANSPORT_PARAMETERS_DRAFT => json!({
            "name": extension_name(*kind),
            "data": hex(data),
            "parameters": list(transport_parameters(data)),
        }),
        APPLICATION_SETTINGS_OLD => json!({
            "name": "application_settings_old (17513)",
            "protocols": list(alps_protocols(data)),
        }),
        APPLICATION_SETTINGS => json!({
            "name": "application_settings (17613)",
            "protocols": list(alps_protocols(data)),
        }),
        kind if is_grease(kind) => json!({ "name": grease_name(kind) }),
        kind => json!({ "name": extension_name(kind), "data": hex(data) }),
    }
}

/// A JSON array, or `null` when empty, as Go marshals a nil slice.
fn list<T: Into<Value>>(items: impl IntoIterator<Item = T>) -> Value {
    let items: Vec<Value> = items.into_iter().map(Into::into).collect();
    if items.is_empty() {
        Value::Null
    } else {
        Value::Array(items)
    }
}

fn status_request(name: &str, data: &[u8]) -> Value {
    let [status_type, responder_ids, request_extensions, ..] = *data else {
        return json!({ "name": name });
    };
    json!({
        "name": name,
        "status_request": {
            // tls.peet.ws's spelling.
            "certificate_status_type": format!("OSCP ({status_type})"),
            "responder_id_list_length": responder_ids,
            "request_extensions_length": request_extensions,
        },
    })
}

/// Signature schemes behind a two-byte length: tls.peet.ws reads `ceil(length / 2)` entries,
/// cut at the data.
fn delegated_credentials(data: &[u8]) -> Vec<u16> {
    let Some((&[hi, lo], rest)) = data.split_first_chunk::<2>() else {
        return Vec::new();
    };
    let count = usize::from(u16::from_be_bytes([hi, lo])).div_ceil(2);
    u16s(rest).take(count).collect()
}

/// `key_share` entries as `{group name: key hex}`. tls.peet.ws needs only `length + 1` bytes
/// of data and reads entries while their offset is below `length`.
fn key_shares(data: &[u8]) -> Vec<Value> {
    let Some((&[hi, lo], _)) = data.split_first_chunk::<2>() else {
        return Vec::new();
    };
    let list_len = usize::from(u16::from_be_bytes([hi, lo]));
    if data.len() <= 2 || data.len() < list_len + 1 {
        return Vec::new();
    }
    let mut shares = Vec::new();
    let mut pos = 2;
    while pos < list_len {
        let Some(&[g0, g1, l0, l1]) = data.get(pos..pos + 4) else {
            break;
        };
        let key_len = usize::from(u16::from_be_bytes([l0, l1]));
        let Some(key) = data.get(pos + 4..pos + 4 + key_len) else {
            break;
        };
        pos += 4 + key_len;
        let mut share = Map::new();
        share.insert(group_name(u16::from_be_bytes([g0, g1])), hex(key).into());
        shares.push(Value::Object(share));
    }
    shares
}

/// ALPS protocol names. tls.peet.ws needs `length + 2` bytes of data and reads names while
/// their offset is below `length`, so a final name of at most one byte can be skipped.
fn alps_protocols(data: &[u8]) -> Vec<String> {
    let Some((&[hi, lo], _)) = data.split_first_chunk::<2>() else {
        return Vec::new();
    };
    let list_len = usize::from(u16::from_be_bytes([hi, lo]));
    if data.len() <= 2 || data.len() < list_len + 2 {
        return Vec::new();
    }
    let mut protocols = Vec::new();
    let mut pos = 2;
    while pos < list_len {
        let Some(&len) = data.get(pos) else { break };
        let Some(name) = data.get(pos + 1..pos + 1 + usize::from(len)) else {
            break;
        };
        pos += 1 + name.len();
        protocols.push(go_string(name));
    }
    protocols
}

/// GREASE as tls.peet.ws prints it in extension details: lowercase hex.
fn grease_name(id: u16) -> String {
    format!("TLS_GREASE (0x{id:04x})")
}

fn group_name(id: u16) -> String {
    if is_grease(id) {
        grease_name(id)
    } else {
        names::curve(id).map_or_else(|| format!("Unknown curve {id}"), str::to_owned)
    }
}

fn signature_name(id: u16) -> String {
    names::signature(id).map_or_else(|| format!("0x{id:x}"), str::to_owned)
}

fn extension_name(id: u16) -> String {
    names::extension(id).map_or_else(
        || format!("Unknown extension {id}"),
        |name| format!("{name} ({id})"),
    )
}

/// tls.peet.ws names four versions and prints the rest as bare lowercase hex.
fn version_name(version: u16) -> String {
    match version {
        0x0304 => "TLS 1.3".to_owned(),
        0x0303 => "TLS 1.2".to_owned(),
        0x0302 => "TLS 1.1".to_owned(),
        0x0301 => "TLS 1.0".to_owned(),
        v if is_grease(v) => grease_name(v),
        v => format!("{v:04x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(kind: u16, data: &[u8]) -> Value {
        details(&Extension {
            kind,
            data: data.to_vec(),
        })
    }

    #[test]
    fn malformed_key_share_stops_without_panicking() {
        // Claims a 32-byte key but carries 2 bytes.
        let got = detail(KEY_SHARE, &[0, 6, 0, 0x1d, 0, 32, 1, 2, 3]);
        assert_eq!(got["shared_keys"], Value::Null);
    }

    #[test]
    fn malformed_alps_stops_without_panicking() {
        // A name claims 9 bytes; only 3 follow.
        let got = detail(APPLICATION_SETTINGS, &[0, 4, 9, b'h', b'2', 0]);
        assert_eq!(got["protocols"], Value::Null);
    }

    #[test]
    fn invalid_utf8_becomes_one_replacement_per_byte() {
        assert_eq!(go_string(b"a\xe2\x82b"), "a\u{fffd}\u{fffd}b");
    }
}
