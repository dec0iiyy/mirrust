//! The HTTP/2 path: `crates/http2` reads the request and writes the frames, the router fills
//! in the body, as tls.peet.ws does.

use std::{io, net::SocketAddr};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    Config,
    report::{Report, TlsDetails},
    routes::{OPTIONS_CONTENT_TYPE, RESPONSE_HEADERS, date, header_value, route, wants_cors},
};

/// Answers one HTTP/2 request with the routed report.
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    syn: Option<tcpip::Syn>,
    tls: TlsDetails,
    config: &Config,
) -> io::Result<()> {
    // The same answer as on HTTP/1.1 and HTTP/3: empty, CORS, `Alt-Svc`, UTF-8 text.
    let options = http2::Response {
        content_type: format!("{OPTIONS_CONTENT_TYPE}; charset=utf-8"),
        allow_cors: true,
        alt_svc: config.alt_svc(),
        ..http2::Response::default()
    };
    // The same on every response of the connection, which has one (RFC 9110 section 6.6.1).
    let date = date();
    let extra_headers: Vec<(&str, &str)> = RESPONSE_HEADERS
        .into_iter()
        .chain([("Date", date.as_str())])
        .collect();
    http2::serve(&mut stream, &extra_headers, options, |request| {
        let allow_cors = wants_cors(
            request.headers().iter().map(String::as_str),
            &config.cors_key,
        );
        let report = Report {
            ip: peer.to_string(),
            http_version: "h2".to_owned(),
            path: request.path.clone(),
            method: request.method.clone(),
            user_agent: request.user_agent.clone(),
            accept: header_value(request.headers().iter().map(String::as_str), "accept"),
            syn,
            tls: Some(tls),
            http2: Some(request.details.clone()),
            ..Report::default()
        };
        let reply = route(&report, config);
        http2::Response {
            status: reply.status,
            content_type: format!("{}; charset=utf-8", reply.content_type),
            body: reply.body,
            allow_cors,
            alt_svc: config.alt_svc(),
        }
    })
    .await
    .map(drop)
    .map_err(into_io)
}

/// The `io::Error` for a failed exchange. A stream failure passes through, so its kind (a
/// timeout, an early EOF) is still known; anything the client sent wrong becomes `InvalidData`
/// that keeps the [`http2::ServeError`], whose `source` is the parser's reason.
fn into_io(error: http2::ServeError) -> io::Error {
    match error {
        http2::ServeError::Io(error) => error,
        error => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

#[cfg(test)]
mod tests {
    use crate::error_chain::error_chain;

    use super::*;

    #[test]
    fn a_protocol_error_keeps_the_parsers_reason() {
        let error = into_io(http2::Error::TooLarge.into());
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error_chain(&error),
            "http/2 client sent invalid input: input exceeds the size limit"
        );
    }

    #[test]
    fn a_stream_error_keeps_its_kind() {
        let error = into_io(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
