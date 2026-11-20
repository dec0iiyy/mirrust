//! Golden snapshots for the workspace's tests.
//!
//! A snapshot is a JSON Lines file under `corpus/`, one line per input case, holding what the
//! code reported for that case when the file was last blessed. [`check`] compares fresh output
//! with it line by line. With the environment variable [`BLESS_VAR`] set to `1`, [`check`]
//! writes the fresh output to the file instead, so an intended change is accepted with
//! `MIRRUST_BLESS=1 cargo test` and reviewed in `git diff`.
//!
//! Lines are written by [`json_line`], which escapes like Go's `encoding/json` (the format
//! tls.peet.ws serves), so an unchanged run rewrites every snapshot byte for byte.

use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;

/// Environment variable that turns [`check`] from comparing into rewriting the snapshot.
pub const BLESS_VAR: &str = "MIRRUST_BLESS";

/// The path of `name` in the workspace's `corpus/` directory.
#[must_use]
pub fn corpus_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(name)
}

/// The contents of `name` in `corpus/`.
///
/// # Panics
///
/// When the file cannot be read.
#[must_use]
pub fn read_corpus(name: &str) -> String {
    let path = corpus_path(name);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {}: {err}", path.display()))
}

/// Whether this run rewrites snapshots instead of checking them.
#[must_use]
pub fn blessing() -> bool {
    env::var(BLESS_VAR).is_ok_and(|value| value == "1")
}

/// `value` as one line of compact JSON, escaped as Go's `encoding/json` escapes it:
/// `<`, `>`, `&`, U+2028 and U+2029 become `\u` escapes.
///
/// Key order is the map's insertion order (`serde_json`'s `preserve_order`).
#[must_use]
pub fn json_line(value: &Value) -> String {
    let text = value.to_string();
    let mut line = String::with_capacity(text.len());
    for c in text.chars() {
        // Outside strings, compact JSON holds none of these characters, so this only touches
        // string contents.
        if matches!(c, '<' | '>' | '&' | '\u{2028}' | '\u{2029}') {
            write!(line, "\\u{:04x}", u32::from(c)).expect("writing to a String cannot fail");
        } else {
            line.push(c);
        }
    }
    line
}

/// Compares `lines` with the snapshot `corpus/<name>`, or rewrites the snapshot when
/// [`blessing`].
///
/// # Panics
///
/// When the snapshot cannot be read or written, or when any line differs from it; the message
/// lists every differing line and, for JSON objects, the keys that differ.
pub fn check(name: &str, lines: &[String]) {
    let path = corpus_path(name);
    if blessing() {
        let mut text = lines.join("\n");
        text.push('\n');
        fs::write(&path, text).unwrap_or_else(|err| panic!("writing {}: {err}", path.display()));
        return;
    }

    let snapshot = read_corpus(name);
    let expected: Vec<&str> = snapshot.lines().collect();
    let mut failures: Vec<String> = lines
        .iter()
        .zip(&expected)
        .enumerate()
        .filter(|(_, (got, want))| got.as_str() != **want)
        .map(|(index, (got, want))| describe(index + 1, got, want))
        .collect();
    if lines.len() != expected.len() {
        failures.push(format!(
            "{} lines produced, {} in the snapshot",
            lines.len(),
            expected.len()
        ));
    }
    assert!(
        failures.is_empty(),
        "{} differs from this run in {} places (rerun with {BLESS_VAR}=1 to accept):\n{}",
        path.display(),
        failures.len(),
        failures.join("\n")
    );
}

/// One failure entry: the keys that differ when both lines are JSON objects, else both lines.
fn describe(line: usize, got: &str, want: &str) -> String {
    let parsed = (
        serde_json::from_str::<Value>(got),
        serde_json::from_str::<Value>(want),
    );
    let (Ok(Value::Object(got)), Ok(Value::Object(want))) = parsed else {
        return format!("line {line}:\n  want {want}\n  got  {got}");
    };
    let name = got.get("name").map_or_else(String::new, Value::to_string);
    let keys = want
        .keys()
        .chain(got.keys().filter(|key| !want.contains_key(*key)));
    let mut out = format!("line {line} {name}:");
    for key in keys {
        let (got_value, want_value) = (got.get(key), want.get(key));
        if got_value != want_value {
            let show = |value: Option<&Value>| {
                value.map_or_else(|| "(absent)".to_owned(), Value::to_string)
            };
            write!(
                out,
                "\n  {key}:\n    want {}\n    got  {}",
                show(want_value),
                show(got_value)
            )
            .expect("writing to a String cannot fail");
        }
    }
    if got == want {
        // Same values, different bytes: key order or escaping.
        write!(
            out,
            "\n  want {}\n  got  {}",
            Value::Object(want),
            Value::Object(got)
        )
        .expect("writing to a String cannot fail");
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn json_line_escapes_like_go() {
        let value = json!({"path": "/a?x=1&y=<2>", "sep": "\u{2028}", "nul": "\0\n\u{8}"});
        // `@` stands for a backslash-u escape.
        let want = r#"{"path":"/a?x=1@0026y=@003c2@003e","sep":"@2028","nul":"@0000\n\b"}"#
            .replace('@', r"\u");
        assert_eq!(json_line(&value), want);
    }
}
