//! The request summary tls.peet.ws builds from the frames before it answers.

use serde::Serialize;

use crate::akamai::{akamai_fingerprint, md5_hex};
use crate::frame::ParsedFrame;
use crate::parser::Parser;

/// Everything tls.peet.ws takes from an HTTP/2 connection to build its response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Http2Request {
    /// Stream of the last HEADERS frame, which the response goes to (0 when none came).
    pub stream_id: u32,
    /// `:method`, empty when absent.
    pub method: String,
    /// `:path`, empty when absent.
    pub path: String,
    /// `user-agent`, empty when absent.
    pub user_agent: String,
    /// What tls.peet.ws reports under `http2`.
    pub details: Http2Details,
}

/// The `http2` object of a tls.peet.ws response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Http2Details {
    /// See [`akamai_fingerprint`](crate::akamai_fingerprint).
    pub akamai_fingerprint: String,
    /// Lowercase hex MD5 of `akamai_fingerprint`.
    pub akamai_fingerprint_hash: String,
    /// Every client frame up to and including the one that ended the request.
    pub sent_frames: Vec<ParsedFrame>,
}

impl Http2Request {
    /// Builds the summary from whatever `parser` has read so far.
    #[must_use]
    pub fn new(parser: Parser) -> Self {
        let mut request = Self::default();
        if let Some(frame) = parser.header_frame() {
            request.stream_id = frame.stream_id;
            for line in &frame.headers {
                if let Some(v) = header_value(line, ":method") {
                    v.clone_into(&mut request.method);
                }
                if let Some(v) = header_value(line, ":path") {
                    v.clone_into(&mut request.path);
                }
                if let Some(v) = header_value(line, "user-agent") {
                    v.clone_into(&mut request.user_agent);
                }
            }
        }
        let frames = parser.into_frames();
        let fingerprint = akamai_fingerprint(&frames);
        request.details = Http2Details {
            akamai_fingerprint_hash: md5_hex(&fingerprint),
            akamai_fingerprint: fingerprint,
            sent_frames: frames,
        };
        request
    }

    /// Decoded `name: value` lines of the request's HEADERS frame, in wire order.
    #[must_use]
    pub fn headers(&self) -> &[String] {
        self.details
            .sent_frames
            .iter()
            .rev()
            .find(|f| f.frame_type == "HEADERS")
            .map_or(&[], |f| &f.headers)
    }
}

/// A header value as tls.peet.ws finds it: the line only has to start with `prefix`, so `user-agent`
/// also matches `user-agent-x: ...`; an empty value counts as absent.
fn header_value<'l>(line: &'l str, prefix: &str) -> Option<&'l str> {
    if !line.starts_with(prefix) {
        return None;
    }
    line.split_once(": ")
        .map(|(_, value)| value)
        .filter(|v| !v.is_empty())
}
