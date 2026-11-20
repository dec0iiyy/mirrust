//! The HTTP/3 path: quinn and `h3` serve the requests, the ClientHello comes from the client's
//! Initial packets as [`crate::sniff`] read them.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, OnceLock};

use anyhow::Context as _;
use bytes::Bytes;
use fingerprint::Transport;
use h3::error::ConnectionError;
use h3::server::RequestStream;
use http::{Request, Response, header};
use http3::Http3Details;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{
    Endpoint, EndpointConfig, IdleTimeout, Incoming, Runtime as _, TokioRuntime, TransportConfig,
    VarInt,
};
use rustls::ServerConfig;

use crate::h3_tap::{self, TapConnection, UniStreams};
use crate::quic_details::QuicDetails;
use crate::report::{Report, TlsDetails};
use crate::routes::{RESPONSE_HEADERS, route, wants_cors};
use crate::sniff::{ClientHellos, SniffingSocket};
use crate::{CONNECTION_TIMEOUT, Config};

/// QUIC always runs TLS 1.3 (RFC 9001 §4.2).
const TLS13: u16 = 0x0304;

/// Largest request header section `h3` decodes (its `SETTINGS_MAX_FIELD_SECTION_SIZE`, sent to
/// the client). Real browser requests with large cookies stay well under it; a bigger one is
/// answered with 431 and the connection ends.
const MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

/// Requests answered on one connection before the server sends GOAWAY and stops accepting.
/// A browser reuses a connection for a page's worth of requests, far fewer than this.
const MAX_REQUESTS_PER_CONNECTION: usize = 100;

/// Bidirectional streams, which carry requests, a client may have open at once. The server
/// answers them one after another, so more would only queue.
const MAX_BIDI_STREAMS: u32 = 16;

/// Unidirectional streams a client may have open at once. HTTP/3 needs three (control and two
/// QPACK) and clients add a GREASE stream; [`h3_tap`] keeps the first prefixes of up to
/// [`h3_tap::MAX_STREAMS`], which is at least this many.
const MAX_UNI_STREAMS: u32 = 8;
const _: () = assert!(MAX_UNI_STREAMS as usize <= h3_tap::MAX_STREAMS);

/// Bytes a client may send on one stream before the server reads them. It must hold a header
/// section of [`MAX_FIELD_SECTION_SIZE`] plus framing, since `h3` buffers a whole HEADERS frame.
const STREAM_RECEIVE_WINDOW: u32 = 128 * 1024;

/// Bytes a client may send on all streams of a connection before the server reads them: two
/// streams' worth, which bounds what a connection makes the server buffer.
const CONNECTION_RECEIVE_WINDOW: u32 = 256 * 1024;

/// Accepts HTTP/3 connections on `socket` forever, each on its own task.
///
/// A connection that arrives while [`Config::connections`] has no free slot is refused.
///
/// `tls` is the TCP listener's configuration; its certificate is reused with ALPN `h3`.
///
/// # Errors
///
/// Fails when `tls` has no cipher suite QUIC can use or the socket cannot be set up.
pub async fn serve_h3(
    socket: UdpSocket,
    tls: Arc<ServerConfig>,
    config: Arc<Config>,
) -> io::Result<()> {
    let mut tls = Arc::unwrap_or_clone(tls);
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicServerConfig::try_from(tls).map_err(io::Error::other)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(transport_config()?));

    let hellos = Arc::new(ClientHellos::default());
    let runtime = Arc::new(TokioRuntime);
    let socket = SniffingSocket::new(runtime.wrap_udp_socket(socket)?, Arc::clone(&hellos));
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        Arc::new(socket),
        runtime,
    )?;

    while let Some(incoming) = endpoint.accept().await {
        let Some(slot) = config.connections.try_admit() else {
            incoming.refuse();
            continue;
        };
        let hellos = Arc::clone(&hellos);
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            let _slot = slot;
            let peer = incoming.remote_address();
            let handled =
                tokio::time::timeout(CONNECTION_TIMEOUT, handle(incoming, &hellos, &config)).await;
            match handled {
                Ok(Ok(())) => {}
                Ok(Err(error)) => config.failures.record_h3(peer, &error),
                Err(_) => config.failures.record_timeout(peer),
            }
        });
    }
    Ok(())
}

/// The limits quinn enforces on each connection, so a client cannot make the server buffer or
/// wait for more than a mirrust request needs.
fn transport_config() -> io::Result<TransportConfig> {
    let idle_timeout = IdleTimeout::try_from(CONNECTION_TIMEOUT).map_err(io::Error::other)?;
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_BIDI_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(MAX_UNI_STREAMS))
        .stream_receive_window(VarInt::from_u32(STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(CONNECTION_RECEIVE_WINDOW))
        // Nothing here reads QUIC datagrams (RFC 9221). quinn would otherwise advertise them and
        // buffer 1.25 MB of them per connection, which flow control does not limit.
        .datagram_receive_buffer_size(None)
        .max_idle_timeout(Some(idle_timeout));
    Ok(transport)
}

/// What is known about a connection's client before its first request.
struct Client {
    peer: SocketAddr,
    tls: Option<TlsDetails>,
    quic: Option<QuicDetails>,
    /// What the client's unidirectional streams have shown so far.
    streams: UniStreams,
    /// The `http3` object, built from `streams` when the first request is answered and
    /// repeated on later requests, so that one connection reports one value.
    http3: OnceLock<Http3Details>,
}

/// Completes the handshake and answers every request on the connection.
async fn handle(incoming: Incoming, hellos: &ClientHellos, config: &Config) -> anyhow::Result<()> {
    let peer = incoming.remote_address();
    let dcid = incoming.orig_dst_cid();
    let connection = incoming.await.context("QUIC handshake")?;
    // Every Initial datagram passed the sniffer before quinn finished the handshake.
    let initial = hellos.take(peer, &dcid);
    let (connection, streams) = TapConnection::new(h3_quinn::Connection::new(connection));
    let client = Client {
        peer,
        streams,
        http3: OnceLock::new(),
        tls: initial
            .as_ref()
            .map(|initial| TlsDetails::new(initial.client_hello(), TLS13, Transport::Quic)),
        quic: initial.as_ref().map(QuicDetails::new),
    };

    let mut h3 = h3::server::builder()
        .max_field_section_size(MAX_FIELD_SECTION_SIZE)
        .build::<_, Bytes>(connection)
        .await
        .context("HTTP/3 setup")?;
    let mut answered = 0;
    loop {
        let resolver = match h3.accept().await {
            Ok(Some(resolver)) => resolver,
            // The client hung up (browsers close without H3_NO_ERROR); nothing went wrong here.
            Ok(None) | Err(ConnectionError::Remote { .. }) => return Ok(()),
            Err(error) if error.is_h3_no_error() => return Ok(()),
            Err(error) => return Err(error).context("accepting a request"),
        };
        let (request, stream) = resolver
            .resolve_request()
            .await
            .context("reading a request")?;
        respond(&request, stream, &client, config).await?;
        answered += 1;
        if answered == MAX_REQUESTS_PER_CONNECTION {
            // GOAWAY: the client opens a new connection for its next request. Requests that
            // arrive after it are rejected, and the loop ends when the client hangs up or the
            // connection's time runs out.
            h3.shutdown(0).await.context("closing the connection")?;
        }
    }
}

/// Answers one request with the routed report, as the HTTP/2 path does.
async fn respond(
    request: &Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    client: &Client,
    config: &Config,
) -> anyhow::Result<()> {
    let options = request.method() == http::Method::OPTIONS;
    let cors = options
        || wants_cors(
            request.headers().keys().map(http::HeaderName::as_str),
            &config.cors_key,
        );
    let (status, body, content_type) = if options {
        (200, Vec::new(), "text/plain")
    } else {
        let report = Report {
            ip: client.peer.to_string(),
            http_version: "h3".to_owned(),
            path: request
                .uri()
                .path_and_query()
                .map_or("/", |path| path.as_str())
                .to_owned(),
            method: request.method().to_string(),
            user_agent: request
                .headers()
                .get(header::USER_AGENT)
                .and_then(|agent| agent.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
            accept: request
                .headers()
                .get_all(header::ACCEPT)
                .iter()
                .filter_map(|accept| accept.to_str().ok())
                .collect::<Vec<_>>()
                .join(", "),
            tls: client.tls.clone(),
            quic: client.quic.clone(),
            http3: Some(
                client
                    .http3
                    .get_or_init(|| client.streams.details())
                    .clone(),
            ),
            ..Report::default()
        };
        let reply = route(&report, config);
        (reply.status, reply.body, reply.content_type)
    };

    let mut response = Response::builder()
        .status(status)
        .header(
            header::CONTENT_TYPE,
            format!("{content_type}; charset=utf-8"),
        )
        .header(header::CONTENT_LENGTH, body.len())
        .header(header::SERVER, "mirrust");
    for (name, value) in RESPONSE_HEADERS {
        response = response.header(name, value);
    }
    if let Some(alt_svc) = config.alt_svc() {
        response = response.header(header::ALT_SVC, alt_svc);
    }
    if cors {
        for name in [
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            header::ACCESS_CONTROL_ALLOW_METHODS,
            header::ACCESS_CONTROL_ALLOW_HEADERS,
        ] {
            response = response.header(name, "*");
        }
    }
    let response = response.body(()).context("building the response head")?;
    stream
        .send_response(response)
        .await
        .context("sending the response head")?;
    // The headers of a HEAD response are those of the GET, but it carries no content
    // (RFC 9110 section 9.3.2).
    if request.method() != http::Method::HEAD {
        stream
            .send_data(Bytes::from(body))
            .await
            .context("sending the body")?;
    }
    stream.finish().await.context("finishing the stream")?;
    Ok(())
}
