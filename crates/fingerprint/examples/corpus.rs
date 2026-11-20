//! Prints the spec JA4 of every ClientHello in a corpus file: `name<TAB>ja4`.
//!
//! `cargo run -p fingerprint --example corpus -- corpus/hellos.jsonl`

use std::{env, fs};

use fingerprint::{ClientHello, Ja4, Transport};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: corpus <hellos.jsonl>")?;
    for line in fs::read_to_string(path)?.lines() {
        let name = field(line, "name").ok_or("line without a name")?;
        let hex = field(line, "hex").ok_or("line without hex")?;
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()?;
        let ja4 = Ja4::new(&ClientHello::parse(&bytes), Transport::Tcp);
        println!("{name}\t{}", ja4.hashed());
    }
    Ok(())
}

/// The string value of `"key":"…"` in a flat JSON line (the corpus has no escapes).
fn field<'line>(line: &'line str, key: &str) -> Option<&'line str> {
    let start = line.find(&format!("\"{key}\":\""))? + key.len() + 4;
    let len = line[start..].find('"')?;
    Some(&line[start..start + len])
}
