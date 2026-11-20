//! What a request reports about its client, and its JSON in tls.peet.ws's format (Go's
//! `encoding/json` conventions).

use std::fmt::Write;

use fingerprint::known::{self, Match};
use fingerprint::{ClientHello, Ja3, Ja4, Ja4Peet, PeetPrint, Transport};
use serde_json::{Value, json};

use crate::client_match;
use crate::quic_details::QuicDetails;

/// The `tls` object of a report.
#[derive(Debug, Clone, Default)]
pub(crate) struct TlsDetails {
    pub(crate) ciphers: Vec<String>,
    pub(crate) extensions: Value,
    pub(crate) record_version: u16,
    pub(crate) negotiated_version: u16,
    pub(crate) ja3: String,
    pub(crate) ja3_hash: String,
    /// JA4 per the FoxIO specification, and its raw and original-order forms.
    pub(crate) ja4: String,
    pub(crate) ja4_r: String,
    pub(crate) ja4_o: String,
    pub(crate) ja4_ro: String,
    /// JA4 as tls.peet.ws reports it under `ja4`/`ja4_r`.
    pub(crate) ja4_peet: String,
    pub(crate) ja4_peet_r: String,
    /// The known client the FoxIO JA4 matches; reported in the top-level `client` object.
    pub(crate) known: Match,
    pub(crate) peetprint: String,
    pub(crate) peetprint_hash: String,
    pub(crate) client_random: String,
    pub(crate) session_id: String,
    /// The ClientHello message as received, from its type byte on.
    pub(crate) raw: Vec<u8>,
}

impl TlsDetails {
    /// Fingerprints `message` (a ClientHello handshake message) the way tls.peet.ws does,
    /// except that `ja4` follows the FoxIO specification and tls.peet.ws's JA4 is `ja4_peet`.
    /// `transport` picks the JA4 prefix: `t` for TCP, `q` for QUIC.
    pub(crate) fn new(message: &[u8], negotiated_version: u16, transport: Transport) -> Self {
        let hello = ClientHello::parse_peet(message);
        let ja3 = Ja3::new(&hello);
        let ja4 = Ja4::new(&ClientHello::parse(message), transport);
        let ja4_peet = Ja4Peet::new(&hello, negotiated_version, transport);
        let peet = PeetPrint::new(&hello);
        Self {
            ciphers: hello.readable_ciphers(),
            extensions: hello.extension_details(),
            record_version: hello.legacy_version,
            negotiated_version,
            ja3: ja3.text().to_owned(),
            ja3_hash: ja3.hash().to_owned(),
            ja4: ja4.hashed().to_owned(),
            ja4_r: ja4.raw().to_owned(),
            ja4_o: ja4.original().to_owned(),
            ja4_ro: ja4.raw_original().to_owned(),
            ja4_peet: ja4_peet.hashed().to_owned(),
            ja4_peet_r: ja4_peet.raw().to_owned(),
            known: known::lookup(&ja4),
            peetprint: peet.text().to_owned(),
            peetprint_hash: peet.hash().to_owned(),
            client_random: hex(&hello.random),
            session_id: hex(&hello.session_id),
            raw: message.to_vec(),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "ciphers": self.ciphers,
            "extensions": self.extensions,
            "tls_version_record": self.record_version.to_string(),
            "tls_version_negotiated": self.negotiated_version.to_string(),
            "ja3": self.ja3,
            "ja3_hash": self.ja3_hash,
            "ja4": self.ja4,
            "ja4_r": self.ja4_r,
            "ja4_o": self.ja4_o,
            "ja4_ro": self.ja4_ro,
            "ja4_peet": self.ja4_peet,
            "ja4_peet_r": self.ja4_peet_r,
            "peetprint": self.peetprint,
            "peetprint_hash": self.peetprint_hash,
            "client_random": self.client_random,
            "session_id": self.session_id,
        })
    }
}

/// The full report, `/api/all`.
#[derive(Debug, Clone, Default)]
pub(crate) struct Report {
    pub(crate) ip: String,
    pub(crate) http_version: String,
    pub(crate) path: String,
    pub(crate) method: String,
    /// Left out of the JSON when empty.
    pub(crate) user_agent: String,
    /// The request's `Accept` header values joined with `, `; empty when it has none. Not in the
    /// JSON: the router reads it to choose between the page and the text report.
    pub(crate) accept: String,
    pub(crate) tls: Option<TlsDetails>,
    /// HTTP/1 header lines in order; `None` leaves `http1` out of the JSON.
    pub(crate) http1_headers: Option<Vec<String>>,
    /// The HTTP/1 request head did not fit the read buffer or ended early, so `http1_headers` may
    /// lack headers the client sent. The audit then does not judge the headers.
    pub(crate) http1_cut: bool,
    /// HTTP/2 frames and Akamai fingerprint; `None` leaves `http2` out of the JSON.
    pub(crate) http2: Option<http2::Http2Details>,
    /// What the QUIC Initial packets show; `None` leaves `quic` out of the JSON.
    pub(crate) quic: Option<QuicDetails>,
    /// HTTP/3 SETTINGS, stream types and their fingerprint; `None` leaves `http3` out of the
    /// JSON.
    pub(crate) http3: Option<http3::Http3Details>,
}

impl Report {
    /// Field order and omissions follow the Go struct tags.
    pub(crate) fn to_json(&self) -> Value {
        let mut out = json!({
            "ip": self.ip,
            "http_version": self.http_version,
            "method": self.method,
        });
        let fields = out.as_object_mut().expect("json! object literal");
        if !self.user_agent.is_empty() {
            fields.insert("user_agent".into(), self.user_agent.clone().into());
        }
        fields.insert(
            "tls".into(),
            self.tls.as_ref().map_or(Value::Null, TlsDetails::to_json),
        );
        if let Some(headers) = &self.http1_headers {
            fields.insert("http1".into(), json!({ "headers": nil_if_empty(headers) }));
        }
        if let Some(details) = &self.http2 {
            fields.insert(
                "http2".into(),
                serde_json::to_value(details).expect("HTTP/2 details always serialize"),
            );
        }
        if let Some(details) = &self.quic {
            fields.insert("quic".into(), details.to_json());
        }
        if let Some(details) = &self.http3 {
            fields.insert(
                "http3".into(),
                serde_json::to_value(details).expect("HTTP/3 details always serialize"),
            );
        }
        // `tcpip` is a non-pointer struct whose `ip` and `tcp` are structs too, so Go's
        // `omitempty` never drops them, even with packet capture off.
        fields.insert("tcpip".into(), json!({ "ip": {}, "tcp": {} }));
        fields.insert("client".into(), self.client_json());
        fields.insert("audit".into(), self.audit_json());
        out
    }

    /// The `client` object: the known client the TLS fingerprint matches and whether the
    /// `User-Agent` agrees. mirrust's own field, not part of tls.peet.ws's layout.
    pub(crate) fn client_json(&self) -> Value {
        let known = self.tls.as_ref().map_or(Match::Unknown, |tls| tls.known);
        client_match::to_json(known, &self.user_agent)
    }

    /// The `audit` object: whether the layers the server observed agree with each other and
    /// with what the `User-Agent` claims, as a score and a list of checks. `null` without a
    /// captured ClientHello. mirrust's own field.
    fn audit_json(&self) -> Value {
        self.audit().map_or(Value::Null, |audit| {
            serde_json::to_value(audit).expect("an audit always serializes")
        })
    }

    /// The audit of this connection; `None` without a captured ClientHello.
    pub(crate) fn audit(&self) -> Option<audit::Audit> {
        let tls = self.tls.as_ref()?;
        let hello = ClientHello::parse(&tls.raw);
        let mut input = audit::Input::new(&hello, &self.user_agent);
        input.known = tls.known;
        input.akamai = self
            .http2
            .as_ref()
            .map(|details| details.akamai_fingerprint.as_str());
        input.headers = if self.http1_cut {
            None
        } else {
            self.http1_headers.as_deref().or_else(|| {
                let frames = &self.http2.as_ref()?.sent_frames;
                let request = frames.iter().rev().find(|f| f.frame_type == "HEADERS")?;
                Some(request.headers.as_slice())
            })
        };
        Some(audit::audit(&input))
    }

    /// The fingerprints-only report (`/api/clean`). Without HTTP/2 the Akamai fields are `-`.
    pub(crate) fn clean_json(&self) -> Value {
        let tls = self.tls.clone().unwrap_or_default();
        let (akamai, akamai_hash) = self.http2.as_ref().map_or(("-", "-"), |h2| {
            (
                h2.akamai_fingerprint.as_str(),
                h2.akamai_fingerprint_hash.as_str(),
            )
        });
        let mut out = json!({
            "ja3": tls.ja3,
            "ja3_hash": tls.ja3_hash,
            "ja4": tls.ja4,
            "ja4_r": tls.ja4_r,
            "ja4_peet": tls.ja4_peet,
            "ja4_peet_r": tls.ja4_peet_r,
            "akamai": akamai,
            "akamai_hash": akamai_hash,
            "peetprint": tls.peetprint,
            "peetprint_hash": tls.peetprint_hash,
            "http_version": self.http_version,
        });
        out["client"] = self.client_json();
        let audit = self.audit_json();
        out["audit"] = if audit.is_null() {
            Value::Null
        } else {
            json!({ "score": audit["score"], "verdict": audit["verdict"] })
        };
        out
    }
}

/// A list that tls.peet.ws writes as `null`, not `[]`, when it is empty.
fn nil_if_empty(items: &[String]) -> Value {
    if items.is_empty() {
        Value::Null
    } else {
        items.into()
    }
}

/// `json.MarshalIndent(v, "", "  ")`.
pub(crate) fn to_go_json_pretty(value: &Value) -> String {
    escape_html(serde_json::to_string_pretty(value).expect("a Value always serializes"))
}

/// `json.Marshal(v)`.
pub(crate) fn to_go_json(value: &Value) -> String {
    escape_html(value.to_string())
}

/// Go's encoder escapes `<`, `>`, `&`, U+2028 and U+2029 inside strings. Those characters
/// cannot appear in JSON outside a string, so escaping the whole text is safe.
fn escape_html(json: String) -> String {
    const SPECIAL: [char; 5] = ['<', '>', '&', '\u{2028}', '\u{2029}'];
    if !json.contains(SPECIAL) {
        return json;
    }
    let mut out = String::with_capacity(json.len() + 32);
    for c in json.chars() {
        if SPECIAL.contains(&c) {
            write!(out, "\\u{:04x}", u32::from(c)).expect("writing to a String cannot fail");
        } else {
            out.push(c);
        }
    }
    out
}

/// Lowercase hex, as Go's `hex.EncodeToString`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            write!(out, "{b:02x}").expect("writing to a String cannot fail");
            out
        })
}

/// Standard padded base64, as Go's `base64.StdEncoding`.
pub(crate) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_go() {
        let value = json!({ "h": ["X: a<b&c>\u{2028}"] });
        assert_eq!(
            to_go_json(&value),
            "{\"h\":[\"X: a\\u003cb\\u0026c\\u003e\\u2028\"]}"
        );
    }

    #[test]
    fn base64_matches_std_encoding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn report_field_order_and_omissions() {
        let report = Report {
            ip: "127.0.0.1:1".into(),
            http_version: "--".into(),
            method: "--".into(),
            ..Report::default()
        };
        let keys: Vec<String> = report
            .to_json()
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            keys,
            [
                "ip",
                "http_version",
                "method",
                "tls",
                "tcpip",
                "client",
                "audit"
            ]
        );
    }

    #[test]
    fn clean_report_without_a_client_hello_has_a_null_audit() {
        let report = Report::default();
        assert_eq!(report.clean_json()["audit"], Value::Null);
        assert_eq!(report.to_json()["audit"], Value::Null);
    }

    /// The checks the audit reports for `report`, by id.
    fn check_ids(report: &Report) -> Vec<String> {
        let audit = report.audit_json();
        audit["checks"]
            .as_array()
            .map(|checks| {
                checks
                    .iter()
                    .filter_map(|check| check["id"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn a_cut_http1_head_is_not_judged_for_missing_headers() {
        let chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like \
                      Gecko) Chrome/160.0.0.0 Safari/537.36";
        let mut report = Report {
            user_agent: chrome.into(),
            tls: Some(TlsDetails::default()),
            http1_headers: Some(vec![format!("User-Agent: {chrome}")]),
            ..Report::default()
        };
        assert!(check_ids(&report).contains(&"headers".to_owned()));

        report.http1_cut = true;
        assert!(!check_ids(&report).contains(&"headers".to_owned()));
    }
}
