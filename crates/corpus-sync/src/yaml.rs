//! The subset of YAML that curl-impersonate's signature files use, read into JSON values.
//!
//! Block mappings and sequences by indentation, plain and quoted scalars (also over several
//! lines), block scalars (`|`, `>`, `!!binary |`) and the empty flow collections `[]` and `{}`.
//! Anchors, aliases, non-empty flow collections and multiple documents are not supported; a
//! value written that way is read as a string, which the caller then rejects as missing detail.

use anyhow::{Result, bail};
use serde_json::{Map, Value};

struct Line {
    indent: usize,
    text: String,
}

struct Parser {
    lines: Vec<Line>,
    pos: usize,
}

/// Parses one YAML document.
///
/// # Errors
///
/// Returns an error when the indentation does not form a mapping or a sequence.
pub fn parse(source: &str) -> Result<Value> {
    let lines = source
        .lines()
        .filter_map(|raw| {
            let text = raw.trim_start_matches(' ');
            let text = text.trim_end();
            (!text.is_empty() && !text.starts_with('#') && text != "---").then(|| Line {
                indent: raw.len() - raw.trim_start_matches(' ').len(),
                text: text.to_owned(),
            })
        })
        .collect();
    let mut parser = Parser { lines, pos: 0 };
    let value = parser.node(0)?;
    if let Some(line) = parser.lines.get(parser.pos) {
        bail!("unexpected indentation at {:?}", line.text);
    }
    Ok(value)
}

impl Parser {
    fn peek(&self) -> Option<&Line> {
        self.lines.get(self.pos)
    }

    /// Parses the node that starts at the current line, if it is indented at least `min`.
    fn node(&mut self, min: usize) -> Result<Value> {
        let Some(line) = self.peek() else {
            return Ok(Value::Null);
        };
        if line.indent < min {
            return Ok(Value::Null);
        }
        let indent = line.indent;
        if is_item(&line.text) {
            self.sequence(indent)
        } else if map_entry(&line.text).is_some() {
            self.mapping(indent)
        } else {
            let first = line.text.clone();
            self.pos += 1;
            self.scalar(&first, indent.saturating_sub(1))
        }
    }

    fn sequence(&mut self, indent: usize) -> Result<Value> {
        let mut items = Vec::new();
        while let Some(line) = self.peek() {
            if line.indent != indent || !is_item(&line.text) {
                break;
            }
            let rest = line.text[1..].trim_start_matches(' ');
            if rest.is_empty() {
                self.pos += 1;
                items.push(self.node(indent + 1)?);
            } else if map_entry(rest).is_some() {
                // `- key: value`: the entry and the lines under it form a mapping indented to
                // where `key` starts.
                let column = indent + (line.text.len() - rest.len());
                self.lines[self.pos] = Line {
                    indent: column,
                    text: rest.to_owned(),
                };
                items.push(self.mapping(column)?);
            } else {
                let first = rest.to_owned();
                self.pos += 1;
                items.push(self.scalar(&first, indent)?);
            }
        }
        Ok(Value::Array(items))
    }

    fn mapping(&mut self, indent: usize) -> Result<Value> {
        let mut map = Map::new();
        while let Some(line) = self.peek() {
            if line.indent < indent {
                break;
            }
            let Some((key, rest)) = map_entry(&line.text).filter(|_| line.indent == indent) else {
                bail!("unexpected line in a mapping: {:?}", line.text);
            };
            let (key, rest) = (key.to_owned(), rest.to_owned());
            self.pos += 1;
            let value = if rest.is_empty() {
                match self.peek() {
                    Some(next) if next.indent == indent && is_item(&next.text) => {
                        self.sequence(indent)?
                    }
                    Some(next) if next.indent > indent => self.node(indent + 1)?,
                    _ => Value::Null,
                }
            } else if is_block_scalar(&rest) {
                self.block_scalar(indent)
            } else {
                self.scalar(&rest, indent)?
            };
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }

    /// Reads the lines of a block scalar: every following line indented more than `indent`.
    fn block_scalar(&mut self, indent: usize) -> Value {
        let mut text = Vec::new();
        while let Some(line) = self.peek().filter(|line| line.indent > indent) {
            text.push(line.text.clone());
            self.pos += 1;
        }
        Value::String(text.join("\n"))
    }

    /// Reads a scalar that starts with `first` and continues on the following lines indented
    /// more than `indent`.
    fn scalar(&mut self, first: &str, indent: usize) -> Result<Value> {
        let mut text = first.to_owned();
        let quote = text.chars().next().filter(|c| *c == '\'' || *c == '"');
        let closed = |text: &str| quote.is_none_or(|q| quoted_end(text, q).is_some());
        while !closed(&text) || quote.is_none() {
            match self.peek() {
                Some(line) if line.indent > indent && (quote.is_some() || !is_item(&line.text)) => {
                    text.push(' ');
                    text.push_str(&line.text);
                    self.pos += 1;
                }
                _ if quote.is_none() => break,
                _ => bail!("unterminated quoted scalar {first:?}"),
            }
        }
        Ok(match quote {
            Some(q) => {
                let end = quoted_end(&text, q).unwrap_or(text.len());
                Value::String(unquote(&text[1..end], q))
            }
            None => plain(&text),
        })
    }
}

fn is_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

fn is_block_scalar(rest: &str) -> bool {
    let rest = rest.strip_prefix("!!binary").map_or(rest, str::trim_start);
    rest.starts_with('|') || rest.starts_with('>')
}

/// Splits `key: value` (or `key:`) when the key is a plain identifier.
fn map_entry(text: &str) -> Option<(&str, &str)> {
    let end = text.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))?;
    if end == 0 {
        return None;
    }
    let rest = &text[end..];
    if rest == ":" {
        return Some((&text[..end], ""));
    }
    rest.strip_prefix(": ")
        .map(|value| (&text[..end], value.trim_start()))
}

/// The byte offset of the closing quote of a scalar that starts with `quote`.
fn quoted_end(text: &str, quote: char) -> Option<usize> {
    let bytes = text.as_bytes();
    let q = u8::try_from(quote).ok()?;
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if q == b'"' => i += 2,
            b if b == q && q == b'\'' && bytes.get(i + 1) == Some(&q) => i += 2,
            b if b == q => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn unquote(inner: &str, quote: char) -> String {
    if quote == '\'' {
        return inner.replace("''", "'");
    }
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

fn plain(text: &str) -> Value {
    match text {
        "[]" => Value::Array(Vec::new()),
        "{}" => Value::Object(Map::new()),
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "null" | "~" => Value::Null,
        _ => text
            .parse::<i64>()
            .map_or_else(|_| Value::String(text.to_owned()), Value::from),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn reads_the_signature_subset() {
        let source = "\
# comment
browser:
  name: chrome
  version: '152'
list:
- GREASE
- 4865
- key: 1
  value: 2
- 'a: ''b'' c
    d'
- plain
  continued
- type: x
  data: !!binary |
    AA==
  empty: []
nested:
  inner:
    deep: \"q\\\"x\"
  last: 18.4
";
        let value = parse(source).expect("the sample parses");
        assert_eq!(
            value,
            json!({
                "browser": {"name": "chrome", "version": "152"},
                "list": ["GREASE", 4865, {"key": 1, "value": 2}, "a: 'b' c d", "plain continued",
                         {"type": "x", "data": "AA==", "empty": []}],
                "nested": {"inner": {"deep": "q\"x"}, "last": "18.4"},
            })
        );
    }

    #[test]
    fn rejects_broken_indentation() {
        assert!(parse("a:\n  b: 1\n c: 2\n").is_err());
    }
}
