//! Text a client chose, made safe to print on a terminal or in a log.

/// Longest client-chosen field (method, path) a stdout or stderr line carries, in characters
/// of the printed form.
pub(crate) const MAX_PRINTED: usize = 200;

/// `text` as `escape_debug` prints it: newlines, ESC and every other control or invisible
/// character come out as backslash escapes, so the text cannot start a new log line or send
/// terminal escape sequences. Longer than `max` characters printed, it is cut between
/// characters and ends with `…`.
pub(crate) fn printable(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut printed = 0;
    for c in text.chars() {
        let width = c.escape_debug().count();
        if printed + width > max {
            out.push('…');
            break;
        }
        out.extend(c.escape_debug());
        printed += width;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_are_escaped() {
        assert_eq!(
            printable("/a\nGET /forged\r\x1b[31m\u{7f}\u{9b}\u{202e}", 200),
            r"/a\nGET /forged\r\u{1b}[31m\u{7f}\u{9b}\u{202e}"
        );
    }

    #[test]
    fn long_text_is_cut_with_an_ellipsis_without_splitting_an_escape() {
        assert_eq!(printable(&"a".repeat(300), 5), "aaaaa…");
        assert_eq!(printable("abc", 3), "abc");
        // `\u{1b}` takes six characters, so it does not fit in the remaining four.
        assert_eq!(printable("ab\u{1b}", 5), "ab…");
        assert_eq!(printable("\u{e9}\u{e9}", 1), "\u{e9}…");
    }
}
