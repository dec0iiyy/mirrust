//! One curl-impersonate signature: the browser it names, the ClientHello rebuilt from it and
//! the HTTP/2 frames it lists.

use anyhow::{Context, Result, anyhow, bail};
use fingerprint::{ClientHello, Ja4, Transport};
use serde_json::Value;

/// The GREASE value written in place of every `GREASE` entry; JA4 ignores all of them.
const GREASE: u16 = 0x0a0a;

/// What a signature file says, read far enough to hash it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// `browser.name`, such as `chrome`.
    pub browser: String,
    /// `browser.os`, such as `macOS`; empty when absent.
    pub os: String,
    /// `browser.version`, such as `150.0.7871.127`.
    pub version: String,
    /// The FoxIO JA4 of the rebuilt ClientHello.
    pub ja4: String,
    /// Its raw form.
    pub ja4_r: String,
    /// The Akamai fingerprint of the HTTP/2 frames, when the signature has any.
    pub akamai: Option<String>,
}

/// Why a signature yields no entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// `tls_client_hello.partial: true`: derived from profile options, not captured.
    Partial,
    /// A field the hashes need is missing or not understood.
    Incomplete(String),
}

impl Signature {
    /// Reads a parsed signature file.
    ///
    /// # Errors
    ///
    /// Returns [`Skip::Partial`] for derived signatures and [`Skip::Incomplete`] when a field
    /// the hashes need is missing or has a form this reader does not know.
    pub fn from_value(doc: &Value) -> Result<Self, Skip> {
        let hello = &doc["signature"]["tls_client_hello"];
        if hello["partial"] == Value::Bool(true) {
            return Err(Skip::Partial);
        }
        let incomplete = |error: anyhow::Error| Skip::Incomplete(format!("{error:#}"));
        let browser = &doc["browser"];
        let text = |value: &Value| match value {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        };
        let name = text(&browser["name"]).ok_or_else(|| incomplete(anyhow!("no browser.name")))?;
        let version =
            text(&browser["version"]).ok_or_else(|| incomplete(anyhow!("no browser.version")))?;
        let message = client_hello(hello).map_err(incomplete)?;
        let ja4 = Ja4::new(&ClientHello::parse(&message), Transport::Tcp);
        let akamai = akamai(&doc["signature"]["http2"]).map_err(incomplete)?;
        Ok(Self {
            browser: name,
            os: text(&browser["os"]).unwrap_or_default(),
            version,
            ja4: ja4.hashed().to_owned(),
            ja4_r: ja4.raw().to_owned(),
            akamai,
        })
    }
}

fn list<'a>(value: &'a Value, what: &str) -> Result<&'a [Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .with_context(|| format!("no list {what}"))
}

/// A 16-bit code point: a number, `GREASE` or a `TLS_VERSION_1_x` name.
fn code(value: &Value) -> Result<u16> {
    match value {
        Value::Number(n) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .with_context(|| format!("{n} is not a 16-bit value")),
        Value::String(s) => match s.as_str() {
            "GREASE" => Ok(GREASE),
            "TLS_VERSION_1_0" => Ok(0x0301),
            "TLS_VERSION_1_1" => Ok(0x0302),
            "TLS_VERSION_1_2" => Ok(0x0303),
            "TLS_VERSION_1_3" => Ok(0x0304),
            other => bail!("unknown value {other:?}"),
        },
        other => bail!("unexpected value {other}"),
    }
}

fn codes(value: &Value, what: &str) -> Result<Vec<u16>> {
    list(value, what)?.iter().map(code).collect()
}

/// The IANA number of an extension named as curl-impersonate's signatures name it.
fn extension_type(name: &str) -> Result<u16> {
    Ok(match name {
        "GREASE" => GREASE,
        "server_name" => 0,
        "status_request" => 5,
        "supported_groups" => 10,
        "ec_point_formats" => 11,
        "signature_algorithms" => 13,
        "application_layer_protocol_negotiation" => 16,
        "signed_certificate_timestamp" => 18,
        "padding" => 21,
        "extended_master_secret" => 23,
        "compress_certificate" => 27,
        "record_size_limit" => 28,
        "delegated_credentials" => 34,
        "session_ticket" => 35,
        "pre_shared_key" => 41,
        "early_data" => 42,
        "supported_versions" => 43,
        "psk_key_exchange_modes" => 45,
        "post_handshake_auth" => 49,
        "keyshare" => 51,
        "application_settings" => 17513,
        "application_settings_new" => 17613,
        "trust_anchors" => 51764,
        "encrypted_client_hello" => 65037,
        "renegotiation_info" => 65281,
        other => bail!("unknown extension type {other:?}"),
    })
}

fn push_u16s(out: &mut Vec<u8>, values: &[u16]) {
    out.extend(values.iter().flat_map(|v| v.to_be_bytes()));
}

fn with_len16(body: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(body.len()).context("field longer than 65535 bytes")?;
    let mut out = len.to_be_bytes().to_vec();
    out.extend_from_slice(body);
    Ok(out)
}

fn with_len8(body: &[u8]) -> Result<Vec<u8>> {
    let len = u8::try_from(body.len()).context("field longer than 255 bytes")?;
    let mut out = vec![len];
    out.extend_from_slice(body);
    Ok(out)
}

/// The data of one extension: real for the lists JA4 reads, a placeholder otherwise.
fn extension_data(kind: u16, ext: &Value) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    match kind {
        0 => {
            let host = b"example.com";
            let mut name = vec![0];
            name.extend(with_len16(host)?);
            body = with_len16(&name)?;
        }
        10 => {
            push_u16s(
                &mut body,
                &codes(&ext["supported_groups"], "supported_groups")?,
            );
            body = with_len16(&body)?;
        }
        11 => {
            let formats: Vec<u8> = list(&ext["ec_point_formats"], "ec_point_formats")?
                .iter()
                .map(|v| code(v).and_then(|c| u8::try_from(c).context("point format")))
                .collect::<Result<_>>()?;
            body = with_len8(&formats)?;
        }
        13 => {
            push_u16s(&mut body, &codes(&ext["sig_hash_algs"], "sig_hash_algs")?);
            body = with_len16(&body)?;
        }
        16 => {
            for protocol in list(&ext["alpn_list"], "alpn_list")? {
                let name = protocol.as_str().context("ALPN entry is not text")?;
                body.extend(with_len8(name.as_bytes())?);
            }
            body = with_len16(&body)?;
        }
        27 => {
            push_u16s(&mut body, &codes(&ext["algorithms"], "algorithms")?);
            body = with_len8(&body)?;
        }
        43 => {
            push_u16s(
                &mut body,
                &codes(&ext["supported_versions"], "supported_versions")?,
            );
            body = with_len8(&body)?;
        }
        45 => {
            let mode = ext["psk_ke_mode"].as_u64().unwrap_or(1);
            body = with_len8(&[u8::try_from(mode).context("psk_ke_mode")?])?;
        }
        _ => {}
    }
    Ok(body)
}

/// Rebuilds a ClientHello handshake message, from the handshake type byte on.
fn client_hello(hello: &Value) -> Result<Vec<u8>> {
    let ciphers = codes(&hello["ciphersuites"], "tls_client_hello.ciphersuites")?;
    let extensions = list(&hello["extensions"], "tls_client_hello.extensions")?;
    if !extensions
        .iter()
        .any(|e| e["type"] == "supported_versions" && e["supported_versions"].is_array())
    {
        bail!("no supported_versions list");
    }
    let mut ext_bytes = Vec::new();
    for ext in extensions {
        let name = ext["type"].as_str().context("extension without a type")?;
        let kind = extension_type(name)?;
        ext_bytes.extend(kind.to_be_bytes());
        ext_bytes.extend(with_len16(&extension_data(kind, ext)?)?);
    }

    let mut body = vec![0x03, 0x03];
    body.extend([0; 32]);
    body.extend(with_len8(&[0; 32])?);
    let mut cipher_bytes = Vec::new();
    push_u16s(&mut cipher_bytes, &ciphers);
    body.extend(with_len16(&cipher_bytes)?);
    body.extend([1, 0]);
    body.extend(with_len16(&ext_bytes)?);

    let len = u32::try_from(body.len()).context("ClientHello too long")?;
    let mut message = vec![1];
    message.extend(&len.to_be_bytes()[1..]);
    message.extend(body);
    Ok(message)
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(payload.len()).context("frame too long")?;
    let mut out = len.to_be_bytes()[1..].to_vec();
    out.extend([kind, flags]);
    out.extend(stream.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn u32_field(value: &Value, what: &str) -> Result<u32> {
    value
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .with_context(|| format!("no number {what}"))
}

/// A placeholder value for a pseudo-header; the Akamai fingerprint reads only the names.
fn pseudo_value(name: &str) -> &'static str {
    match name {
        ":method" => "GET",
        ":scheme" => "https",
        ":path" => "/",
        _ => "example.com",
    }
}

/// The Akamai fingerprint of the frames in `http2.frames`, through the `http2` crate's parser.
fn akamai(http2: &Value) -> Result<Option<String>> {
    if http2.is_null() {
        return Ok(None);
    }
    let mut wire = http2::PREFACE.to_vec();
    for f in list(&http2["frames"], "http2.frames")? {
        let stream = f["stream_id"]
            .as_u64()
            .map_or(Ok(0), |_| u32_field(&f["stream_id"], "stream_id"))?;
        match f["frame_type"].as_str() {
            Some("SETTINGS") => {
                let mut payload = Vec::new();
                for s in list(&f["settings"], "settings")? {
                    let key = u16::try_from(u32_field(&s["key"], "settings key")?)
                        .context("settings key")?;
                    payload.extend(key.to_be_bytes());
                    payload.extend(u32_field(&s["value"], "settings value")?.to_be_bytes());
                }
                wire.extend(frame(0x4, 0, 0, &payload)?);
            }
            Some("WINDOW_UPDATE") => {
                let increment = u32_field(&f["window_size_increment"], "window_size_increment")?;
                wire.extend(frame(0x8, 0, stream, &increment.to_be_bytes())?);
            }
            Some("HEADERS") => {
                let mut block = Vec::new();
                for name in list(&f["pseudo_headers"], "pseudo_headers")? {
                    let name = name.as_str().context("pseudo-header is not text")?;
                    // HPACK literal without indexing, new name, no Huffman coding.
                    block.push(0);
                    block.extend(with_len8(name.as_bytes())?);
                    block.extend(with_len8(pseudo_value(name).as_bytes())?);
                }
                // END_STREAM | END_HEADERS.
                wire.extend(frame(0x1, 0x5, stream.max(1), &block)?);
            }
            other => bail!("unknown HTTP/2 frame type {other:?}"),
        }
    }
    let mut parser = http2::Parser::new();
    parser
        .feed(&wire)
        .map_err(|error| anyhow!("the http2 parser rejected the frames: {error}"))?;
    Ok(Some(http2::akamai_fingerprint(parser.frames())))
}
