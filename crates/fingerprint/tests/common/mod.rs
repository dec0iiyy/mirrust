//! Helpers shared by the snapshot tests over `corpus/`.

use std::fmt::Write;

use fingerprint::{ClientHello, Ja3, Ja4Peet, PeetPrint, Transport};
use serde_json::{Map, Value};

pub fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("corpus hex is valid"))
        .collect()
}

/// What a TLS server negotiates: 1.3 when offered, else the legacy version.
pub fn negotiated(hello: &ClientHello) -> u16 {
    if hello.supported_versions.contains(&0x0304) {
        0x0304
    } else {
        hello.legacy_version
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").expect("writing to a String cannot fail");
        out
    })
}

/// One snapshot line: the case name, then every field tls.peet.ws reports, under its names.
pub fn snapshot_line(name: &str, hello: &ClientHello) -> String {
    let ja3 = Ja3::new(hello);
    let ja4 = Ja4Peet::new(hello, negotiated(hello), Transport::Tcp);
    let peet = PeetPrint::new(hello);
    let fields: [(&str, Value); 13] = [
        ("name", name.into()),
        ("ciphers", hello.readable_ciphers().into()),
        ("extensions", hello.extension_details()),
        (
            "tls_version_record",
            hello.legacy_version.to_string().into(),
        ),
        (
            "tls_version_negotiated",
            negotiated(hello).to_string().into(),
        ),
        ("ja3", ja3.text().into()),
        ("ja3_hash", ja3.hash().into()),
        ("ja4", ja4.hashed().into()),
        ("ja4_r", ja4.raw().into()),
        ("peetprint", peet.text().into()),
        ("peetprint_hash", peet.hash().into()),
        ("client_random", hex(&hello.random).into()),
        ("session_id", hex(&hello.session_id).into()),
    ];
    let object: Map<String, Value> = fields
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    golden::json_line(&Value::Object(object))
}

/// Each line of a `{"name", "hex"}` corpus as its name and decoded message.
pub fn cases(corpus: &str) -> impl Iterator<Item = (String, Vec<u8>)> {
    corpus.lines().map(|line| {
        let input: Value = serde_json::from_str(line).expect("corpus line is JSON");
        let name = input["name"].as_str().expect("corpus name").to_owned();
        (name, decode_hex(input["hex"].as_str().expect("corpus hex")))
    })
}
