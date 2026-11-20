//! QUIC transport parameters (RFC 9000 §18), which a QUIC client sends in the ClientHello
//! extension `quic_transport_parameters`.

use serde_json::{Value, json};

use crate::text::hex;

/// How a parameter's value is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    /// One variable-length integer filling the whole value.
    Varint,
    /// Anything else: connection ids, tokens, lists, and the empty value of a flag.
    Bytes,
}

/// Name and encoding of the parameters of RFC 9000 §18.2 and of the extensions browsers send.
fn known(id: u64) -> Option<(&'static str, Encoding)> {
    use Encoding::{Bytes, Varint};
    Some(match id {
        0x00 => ("original_destination_connection_id", Bytes),
        0x01 => ("max_idle_timeout", Varint),
        0x02 => ("stateless_reset_token", Bytes),
        0x03 => ("max_udp_payload_size", Varint),
        0x04 => ("initial_max_data", Varint),
        0x05 => ("initial_max_stream_data_bidi_local", Varint),
        0x06 => ("initial_max_stream_data_bidi_remote", Varint),
        0x07 => ("initial_max_stream_data_uni", Varint),
        0x08 => ("initial_max_streams_bidi", Varint),
        0x09 => ("initial_max_streams_uni", Varint),
        0x0a => ("ack_delay_exponent", Varint),
        0x0b => ("max_ack_delay", Varint),
        0x0c => ("disable_active_migration", Bytes),
        0x0d => ("preferred_address", Bytes),
        0x0e => ("active_connection_id_limit", Varint),
        0x0f => ("initial_source_connection_id", Bytes),
        0x10 => ("retry_source_connection_id", Bytes),
        // RFC 9368.
        0x11 => ("version_information", Bytes),
        // draft-ietf-quic-reliable-stream-reset, an empty flag.
        0x1d => ("reset_stream_at", Bytes),
        // RFC 9221.
        0x20 => ("max_datagram_frame_size", Varint),
        // RFC 10069 section 2.1.
        0x3e => ("initial_max_path_id", Varint),
        // The provisional entries of the IANA "QUIC Transport Parameters" registry that a client
        // may send: Quantum Readiness test, SCONE (draft-ietf-scone-protocol).
        0x173e => ("discard", Bytes),
        0x219e => ("scone_supported", Bytes),
        // RFC 9287.
        0x2ab2 => ("grease_quic_bit", Bytes),
        // Google QUIC (quiche).
        0x26ab => ("google_handshake_message", Bytes),
        0x3127 => ("initial_rtt", Varint),
        0x3128 => ("google_connection_options", Bytes),
        0x3129 => ("user_agent", Bytes),
        0x4752 => ("google_version", Bytes),
        // draft-ietf-quic-version-negotiation before RFC 9368.
        0x00ff_73db => ("version_information_draft", Bytes),
        // The id of min_ack_delay changed with the drafts: 0xde1a in
        // draft-iyengar-quic-delayed-ack-01, 0xff02de1a in delayed-ack-02 and
        // draft-ietf-quic-ack-frequency-00, 0xff03de1a in ack-frequency-01 to -03, 0xff04de1a in
        // -04 to -06, 0xff04de1b from -07 on (the one IANA registers).
        0xde1a | 0xff02_de1a | 0xff03_de1a | 0xff04_de1a | 0xff04_de1b => ("min_ack_delay", Varint),
        _ => return None,
    })
}

/// Whether `id` is reserved to exercise the "ignore unknown parameters" rule: `31 * N + 27`
/// (RFC 9000 §18.1).
const fn is_reserved(id: u64) -> bool {
    id % 31 == 27
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

/// One `{id, name, value}` object per transport parameter in `data`, in the client's order.
///
/// `name` is the RFC name, `GREASE` for a reserved id, `UNKNOWN_<id>` otherwise. `value` is a
/// number when the parameter is defined as one integer and holds exactly that, else the hex of
/// its bytes. The list stops at the first parameter that does not fit in `data`.
pub(crate) fn transport_parameters(data: &[u8]) -> Vec<Value> {
    let mut parameters = Vec::new();
    let mut rest = data;
    while let Some((id, value, next)) = parameter(rest) {
        rest = next;
        // Named ids first: 0xff02de1a, the `min_ack_delay` of the first ack-frequency draft,
        // happens to be of the reserved form.
        let (name, encoding) = if let Some((name, encoding)) = known(id) {
            (name.to_owned(), encoding)
        } else if is_reserved(id) {
            ("GREASE".to_owned(), Encoding::Bytes)
        } else {
            (format!("UNKNOWN_{id}"), Encoding::Bytes)
        };
        let number = match (encoding, varint(value)) {
            (Encoding::Varint, Some((number, []))) => Some(number),
            _ => None,
        };
        parameters.push(json!({
            "id": id,
            "name": name,
            "value": number.map_or_else(|| hex(value).into(), Value::from),
        }));
    }
    parameters
}

/// Splits `(id, value, rest)` off the front of `data`.
fn parameter(data: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    let (id, rest) = varint(data)?;
    let (len, rest) = varint(rest)?;
    let (value, rest) = rest.split_at_checked(usize::try_from(len).ok()?)?;
    Some((id, value, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_integers_bytes_flags_grease_and_unknown_ids_in_wire_order() {
        let data = [
            &[0x04, 0x04, 0x80, 0xf0, 0x00, 0x00][..], // initial_max_data = 15728640
            &[0x0f, 0x00],                             // initial_source_connection_id, empty
            &[0x6a, 0xb2, 0x00],                       // grease_quic_bit (0x2ab2), a flag
            &[0x40, 0x3a, 0x02, 0xab, 0xcd],           // 58 = 31 * 1 + 27: reserved
            &[0x7f, 0xff, 0x01, 0x07],                 // 16383: no name
            &[0x80, 0x00, 0x47, 0x52, 0x04, 0x00, 0x00, 0x00, 0x01], // google_version
            &[0x01, 0x02, 0x00, 0x1e],                 // max_idle_timeout = 30, not one varint
        ]
        .concat();
        assert_eq!(
            Value::from(transport_parameters(&data)),
            json!([
                { "id": 4, "name": "initial_max_data", "value": 15_728_640 },
                { "id": 15, "name": "initial_source_connection_id", "value": "" },
                { "id": 10930, "name": "grease_quic_bit", "value": "" },
                { "id": 58, "name": "GREASE", "value": "abcd" },
                { "id": 16383, "name": "UNKNOWN_16383", "value": "07" },
                { "id": 18258, "name": "google_version", "value": "00000001" },
                { "id": 1, "name": "max_idle_timeout", "value": "001e" },
            ])
        );
    }

    #[test]
    fn stops_at_the_first_parameter_that_does_not_fit() {
        let whole = [0x08, 0x02, 0x40, 0x64, 0x09, 0x01, 0x03];
        for len in 0..whole.len() {
            let got = transport_parameters(&whole[..len]);
            assert_eq!(got.len(), usize::from(len >= 4), "prefix of {len} bytes");
        }
        assert_eq!(transport_parameters(&whole).len(), 2);
        // A length of 2^62 - 1 with nothing behind it.
        let huge = [0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(transport_parameters(&huge), Vec::<Value>::new());
    }

    #[test]
    fn a_named_parameter_with_a_reserved_id_keeps_its_name() {
        let named_and_reserved: Vec<u64> = (0..=0x4752)
            .chain([
                0xde1a,
                0xff02_de1a,
                0xff03_de1a,
                0xff04_de1a,
                0xff04_de1b,
                0x00ff_73db,
            ])
            .filter(|&id| is_reserved(id) && known(id).is_some())
            .collect();
        assert_eq!(named_and_reserved, [0xff02_de1a]);
        // min_ack_delay = 1000 under the draft id.
        let data = [0xc0, 0, 0, 0, 0xff, 0x02, 0xde, 0x1a, 0x02, 0x43, 0xe8];
        assert_eq!(
            Value::from(transport_parameters(&data)),
            json!([{ "id": 0xff02_de1a_u32, "name": "min_ack_delay", "value": 1000 }])
        );
    }

    #[test]
    fn names_follow_the_registry_and_the_ack_frequency_drafts() {
        let data = [
            &[0x1d, 0x00][..],                                    // reset_stream_at, a flag
            &[0x3e, 0x01, 0x04],                                  // initial_max_path_id = 4
            &[0x80, 0x00, 0xde, 0x1a, 0x01, 0x05],                // 0xde1a: delayed-ack-01
            &[0xc0, 0, 0, 0, 0xff, 0x03, 0xde, 0x1a, 0x01, 0x06], // ack-frequency-01 to -03
            &[0xc0, 0, 0, 0, 0xff, 0x04, 0xde, 0x1a, 0x01, 0x07], // ack-frequency-04 to -06
        ]
        .concat();
        let names: Vec<(Value, Value)> = transport_parameters(&data)
            .into_iter()
            .map(|parameter| (parameter["name"].clone(), parameter["value"].clone()))
            .collect();
        assert_eq!(
            names,
            [
                (json!("reset_stream_at"), json!("")),
                (json!("initial_max_path_id"), json!(4)),
                (json!("min_ack_delay"), json!(5)),
                (json!("min_ack_delay"), json!(6)),
                (json!("min_ack_delay"), json!(7)),
            ]
        );
    }
}
