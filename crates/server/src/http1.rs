//! HTTP/1.1 over an accepted TLS stream: one request read, parsed and answered.

use std::fmt::Write as _;
use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Config;
use crate::report::{Report, TlsDetails};
use crate::routes::{
    OPTIONS_CONTENT_TYPE, RESPONSE_HEADERS, date, header_value, route, wants_cors,
};

/// The request is read into a 1024-byte buffer once and that buffer is parsed whole,
/// zero padding included.
const REQUEST_BUFFER: usize = 1024;

/// Reads one request, answers it and closes the stream.
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    tls: TlsDetails,
    config: &Config,
) -> io::Result<()> {
    let request = read_request(&mut stream).await?;
    let mut report = parse(&request);
    report.ip = peer.to_string();
    report.tls = Some(tls);

    let options = report.method == "OPTIONS";
    let cors = wants_cors(
        report.http1_headers.iter().flatten().map(String::as_str),
        &config.cors_key,
    );
    let (status, body, content_type) = if options {
        (200, Vec::new(), OPTIONS_CONTENT_TYPE)
    } else {
        let reply = route(&report, config);
        (reply.status, reply.body, reply.content_type)
    };

    let reason = match status {
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nDate: {}\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: {content_type}; charset=utf-8\r\n",
        date(),
        body.len()
    );
    for (name, value) in RESPONSE_HEADERS {
        write!(head, "{name}: {value}\r\n").expect("writing to a String cannot fail");
    }
    if options || cors {
        head.push_str(
            "Access-Control-Allow-Origin: *\r\n\
             Access-Control-Allow-Methods: *\r\n\
             Access-Control-Allow-Headers: *\r\n",
        );
    }
    if let Some(alt_svc) = config.alt_svc() {
        write!(head, "Alt-Svc: {alt_svc}\r\n").expect("writing to a String cannot fail");
    }
    head.push_str("Server: mirrust\r\n\r\n");

    let mut response = head.into_bytes();
    // A response to HEAD has the headers of the GET response, `Content-Length` included, and
    // no content (RFC 9110 section 9.3.2).
    if report.method != "HEAD" {
        response.extend_from_slice(&body);
        // tls.peet.ws writes two CRLFs past Content-Length; so do we, for comparability.
        response.extend_from_slice(b"\r\n\r\n");
    }
    stream.write_all(&response).await?;
    stream.shutdown().await
}

/// Reads until the header block ends, the buffer is full or the client stops sending.
///
/// At most [`REQUEST_BUFFER`] bytes are read and kept, however much the client sends; how long
/// a slow client may take is bounded by the connection's deadline in [`crate::serve`].
async fn read_request<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(REQUEST_BUFFER);
    let mut chunk = [0; REQUEST_BUFFER];
    while request.len() < REQUEST_BUFFER && !request.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream
            .read(&mut chunk[..REQUEST_BUFFER - request.len()])
            .await?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..n]);
    }
    if request.is_empty() {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    request.resize(REQUEST_BUFFER, 0);
    Ok(request)
}

/// The request as tls.peet.ws reads it: every line containing `:` is a header, the request line
/// included; a request line that is not exactly three space-separated parts gives `--`.
fn parse(request: &[u8]) -> Report {
    let text = go_string(request);
    let lines: Vec<&str> = text.split("\r\n").collect();
    let request_line: Vec<&str> = lines[0].split(' ').collect();
    let [method, path, version] = request_line.as_slice() else {
        return Report {
            http_version: "--".into(),
            method: "--".into(),
            path: "--".into(),
            ..Report::default()
        };
    };

    let headers: Vec<String> = lines
        .iter()
        .filter(|line| line.contains(':'))
        .map(|&line| line.to_owned())
        .collect();
    let user_agent = headers
        .iter()
        .filter(|line| line.to_lowercase().starts_with("user-agent"))
        .filter_map(|line| line.split_once(": ").map(|(_, value)| value))
        .rfind(|value| !value.is_empty())
        .unwrap_or_default()
        .trim()
        .to_owned();

    let accept = header_value(headers.iter().map(String::as_str), "accept");

    Report {
        http_version: (*version).to_owned(),
        path: (*path).to_owned(),
        method: (*method).to_owned(),
        user_agent,
        accept,
        http1_headers: Some(headers),
        ..Report::default()
    }
}

/// Go's `string(bytes)` as `encoding/json` later prints it: each invalid byte is U+FFFD.
fn go_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        out.extend(chunk.invalid().iter().map(|_| char::REPLACEMENT_CHARACTER));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn padded(text: &str) -> Vec<u8> {
        let mut bytes = text.as_bytes().to_vec();
        bytes.resize(REQUEST_BUFFER, 0);
        bytes
    }

    #[test]
    fn keeps_header_lines_in_order_and_raw() {
        let report = parse(&padded(
            "GET /api/all HTTP/1.1\r\nHost: x\r\nuser-agent:  curl/8 \r\nAccept: */*\r\n\r\n",
        ));
        assert_eq!(report.method, "GET");
        assert_eq!(report.path, "/api/all");
        assert_eq!(report.http_version, "HTTP/1.1");
        assert_eq!(report.user_agent, "curl/8");
        assert_eq!(report.accept, "*/*");
        assert_eq!(
            report.http1_headers.expect("parsed"),
            ["Host: x", "user-agent:  curl/8 ", "Accept: */*"]
        );
    }

    #[test]
    fn a_bad_request_line_gives_dashes_and_no_headers() {
        let report = parse(&padded("GET /\r\nHost: x\r\n\r\n"));
        assert_eq!(report.method, "--");
        assert_eq!(report.path, "--");
        assert!(report.http1_headers.is_none());
    }

    #[test]
    fn a_colon_in_the_request_line_makes_it_a_header() {
        let report = parse(&padded("GET /a:b HTTP/1.1\r\n\r\n"));
        assert_eq!(report.http1_headers.expect("parsed"), ["GET /a:b HTTP/1.1"]);
    }

    #[tokio::test]
    async fn reading_stops_at_the_buffer_size_without_a_header_end() {
        let sent = vec![b'a'; 3 * REQUEST_BUFFER];
        let mut stream = sent.as_slice();
        let request = read_request(&mut stream).await.expect("read");
        assert_eq!(request, sent[..REQUEST_BUFFER]);
        assert_eq!(stream.len(), 2 * REQUEST_BUFFER, "the rest is left unread");
    }

    #[tokio::test]
    async fn reading_stops_at_the_header_end() {
        let mut stream = &b"GET / HTTP/1.1\r\n\r\n"[..];
        let request = read_request(&mut stream).await.expect("read");
        assert_eq!(request, padded("GET / HTTP/1.1\r\n\r\n"));
    }

    #[test]
    fn invalid_utf8_becomes_one_replacement_per_byte() {
        assert_eq!(go_string(b"a\xff\xfeb"), "a\u{fffd}\u{fffd}b");
    }
}
