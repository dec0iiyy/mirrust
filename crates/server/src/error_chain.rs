//! An error and its causes as one line.

use std::error::Error;

/// `error` followed by each of its sources, separated by `: `.
///
/// `Display` of most errors in this server names only the failing step and leaves the reason
/// to `source()`; a log line needs both.
pub(crate) fn error_chain(error: &(dyn Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn joins_the_error_and_its_sources() {
        let inner = io::Error::other("disk gone");
        let outer = http2::ServeError::from(inner);
        assert_eq!(
            error_chain(&outer),
            "http/2 connection i/o failed: disk gone"
        );
    }

    #[test]
    fn an_error_without_a_source_is_just_its_text() {
        assert_eq!(error_chain(&io::Error::other("alone")), "alone");
    }
}
