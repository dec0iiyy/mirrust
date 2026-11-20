//! HTTP/1.1 over an accepted TLS stream: one request read, parsed and answered.

use std::fmt::Write as _;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Config;
use crate::report::{Report, TlsDetails};
use crate::routes::{
    OPTIONS_CONTENT_TYPE, RESPONSE_HEADERS, date, header_value, route, wants_cors,
};

/// Most bytes of a request that are read: the head of a browser's request with its cookies
/// fits, and a connection cannot make the server hold more. It is what Node.js allows a
/// request head by default; nginx and Apache allow 8 KiB a line.
const MAX_HEAD: usize = 16 * 1024;

/// How long the server reads on after its response for the client to close. The HTTP/2 path
/// waits as long before it closes.
const CLOSE_DELAY: Duration = Duration::from_millis(500);

/// Reads one request, answers it and closes the stream.
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    tls: TlsDetails,
    config: &Config,
) -> io::Result<()> {
    let request = read_request(&mut stream).await?;
    let head = head_end(&request);
    let mut report = parse(&request[..head.unwrap_or(request.len())]);
    report.http1_cut = head.is_none();
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
    }
    stream.write_all(&response).await?;
    stream.shutdown().await?;
    // The request may be longer than what was read: a body, or a head over the limit. Closing
    // a socket that has unread input resets the connection, and the reset can make the client
    // drop the response it has not read yet. A client that got its response closes, which
    // ends the wait at once.
    let unread = async {
        let mut sink = [0; 1024];
        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
    };
    let _ = tokio::time::timeout(CLOSE_DELAY, unread).await;
    Ok(())
}

/// Reads until the request head ends, [`MAX_HEAD`] bytes are in or the client stops sending.
///
/// No more than that is read and kept, however much the client sends; how long a slow client
/// may take is bounded by the connection's deadline in [`crate::serve`].
async fn read_request<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0; 1024];
    // Where the search for the end of the head goes on: what is before holds no empty line.
    let mut searched = 0;
    while request.len() < MAX_HEAD && head_end(&request[searched..]).is_none() {
        // An empty line can begin in the last two bytes read so far.
        searched = request.len().saturating_sub(2);
        let room = chunk.len().min(MAX_HEAD - request.len());
        let n = stream.read(&mut chunk[..room]).await?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..n]);
    }
    if request.is_empty() {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(request)
}

/// Where the request head in `bytes` ends: the index after the first empty line.
///
/// Lines end with CRLF, and a bare LF is taken as a line end too, as RFC 9112 section 2.2
/// allows a recipient: a client that sends bare LFs is answered at once instead of waiting
/// for the connection's deadline.
fn head_end(bytes: &[u8]) -> Option<usize> {
    let mut at = 0;
    while let Some(lf) = bytes[at..].iter().position(|&byte| byte == b'\n') {
        at += lf + 1;
        match bytes[at..] {
            [b'\n', ..] => return Some(at + 1),
            [b'\r', b'\n', ..] => return Some(at + 2),
            _ => {}
        }
    }
    None
}

/// The request line and the header lines of `head`: the lines after the request line that
/// contain a `:`, as they were sent. A request line that is not exactly three space-separated
/// parts gives `--`, as on tls.peet.ws.
fn parse(head: &[u8]) -> Report {
    let text = go_string(head);
    let lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
    let request_line: Vec<&str> = lines[0].split(' ').collect();
    let [method, path, version] = request_line.as_slice() else {
        return Report {
            http_version: "--".into(),
            method: "--".into(),
            path: "--".into(),
            ..Report::default()
        };
    };

    let headers: Vec<String> = lines[1..]
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

    #[test]
    fn keeps_header_lines_in_order_and_raw() {
        let report = parse(
            b"GET /api/all HTTP/1.1\r\nHost: x\r\nuser-agent:  curl/8 \r\nAccept: */*\r\n\r\n",
        );
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
        let report = parse(b"GET /\r\nHost: x\r\n\r\n");
        assert_eq!(report.method, "--");
        assert_eq!(report.path, "--");
        assert!(report.http1_headers.is_none());
    }

    #[test]
    fn the_request_line_is_not_a_header_whatever_it_contains() {
        let report = parse(b"GET /a:b HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(report.path, "/a:b");
        assert_eq!(report.http1_headers.expect("parsed"), ["Host: x"]);
    }

    #[test]
    fn bare_lf_line_ends_are_read_like_crlf() {
        let request = b"GET / HTTP/1.1\nHost: x\nUser-Agent: lf\n\nbody: 1";
        let head = head_end(request).expect("an empty line");
        assert_eq!(&request[head..], b"body: 1");
        let report = parse(&request[..head]);
        assert_eq!(report.http_version, "HTTP/1.1");
        assert_eq!(report.user_agent, "lf");
        assert_eq!(
            report.http1_headers.expect("parsed"),
            ["Host: x", "User-Agent: lf"]
        );
    }

    #[test]
    fn the_head_ends_at_the_first_empty_line() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n\r\nrest"), Some(18));
        assert_eq!(head_end(b"GET / HTTP/1.1\n\nrest"), Some(16));
        assert_eq!(head_end(b"GET / HTTP/1.1\n\r\nrest"), Some(17));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r"), None);
        assert_eq!(head_end(b""), None);
    }

    #[tokio::test]
    async fn reading_stops_at_the_limit_without_a_header_end() {
        let sent = vec![b'a'; 3 * MAX_HEAD];
        let mut stream = sent.as_slice();
        let request = read_request(&mut stream).await.expect("read");
        assert_eq!(request, sent[..MAX_HEAD]);
        assert_eq!(stream.len(), 2 * MAX_HEAD, "the rest is left unread");
    }

    #[tokio::test]
    async fn a_head_larger_than_the_old_1024_bytes_is_read_whole() {
        let cookie = "c".repeat(6000);
        let sent = format!("GET / HTTP/1.1\r\nCookie: {cookie}\r\nAccept: text/html\r\n\r\n");
        let mut stream = sent.as_bytes();
        let request = read_request(&mut stream).await.expect("read");
        assert_eq!(head_end(&request), Some(sent.len()));
        let report = parse(&request);
        assert_eq!(report.accept, "text/html");
        assert_eq!(report.http1_headers.expect("parsed").len(), 2);
    }

    /// A reader that hands out one byte at a time, as a slow client would.
    struct ByteByByte<'a>(&'a [u8]);

    impl AsyncRead for ByteByByte<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if let Some((first, rest)) = self.0.split_first() {
                buf.put_slice(&[*first]);
                self.0 = rest;
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn reading_stops_at_the_header_end_however_the_bytes_arrive() {
        for sent in [
            &b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody"[..],
            b"GET / HTTP/1.1\nHost: x\n\nbody",
        ] {
            let mut stream = ByteByByte(sent);
            let request = read_request(&mut stream).await.expect("read");
            assert_eq!(request, sent[..sent.len() - 4]);
            assert_eq!(stream.0, b"body", "nothing past the head is read");
        }
    }

    #[test]
    fn invalid_utf8_becomes_one_replacement_per_byte() {
        assert_eq!(go_string(b"a\xff\xfeb"), "a\u{fffd}\u{fffd}b");
    }
}
