//! End to end: the `client` object of `/api/all` and `/api/clean` for a rustls client that
//! sends different `User-Agent` values.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use fingerprint::known::{self, AgentFamily, Client, Match};
use fingerprint::{ClientHello, Ja4, Transport};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};
use server::{Config, self_signed_cert, serve, tls_config};
use tokio::runtime::Runtime;

const CHROME: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, \
    like Gecko) Chrome/133.0.0.0 Safari/537.36";

/// Starts the server; the runtime must outlive the requests.
fn start() -> (Runtime, SocketAddr, RootCertStore) {
    let (certs, key) = self_signed_cert().expect("self-signed cert");
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).expect("cert is a usable root");
    let tls = Arc::new(tls_config(certs, key).expect("tls config"));

    let runtime = Runtime::new().expect("tokio runtime");
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    runtime.spawn(serve(listener, tls, Arc::new(Config::default())));
    (runtime, addr, roots)
}

/// Requests `path` over HTTP/1.1 with `user_agent` (no header when empty); returns the JA4
/// of the ClientHello the client sent and the response body as JSON.
fn get(addr: SocketAddr, roots: RootCertStore, path: &str, user_agent: &str) -> (Ja4, Value) {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = ServerName::try_from("localhost").expect("valid name");
    let mut conn = ClientConnection::new(Arc::new(config), name).expect("client connection");

    // The ClientHello is queued as soon as the connection exists; capture it on its way out.
    let mut first_flight = Vec::new();
    conn.write_tls(&mut first_flight).expect("first flight");
    // One record holds the whole message: skip the five-byte record header.
    let ja4 = Ja4::new(&ClientHello::parse(&first_flight[5..]), Transport::Tcp);

    let mut socket = TcpStream::connect(addr).expect("connect");
    socket.write_all(&first_flight).expect("send ClientHello");
    let mut tls = StreamOwned::new(conn, socket);
    let agent_line = if user_agent.is_empty() {
        String::new()
    } else {
        format!("User-Agent: {user_agent}\r\n")
    };
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{agent_line}\r\n");
    tls.write_all(request.as_bytes()).expect("send request");
    let mut response = Vec::new();
    // The server closes after one response; a missing close_notify is not this test's concern.
    let _ = tls.read_to_end(&mut response);

    let response = String::from_utf8(response).expect("UTF-8 response");
    let (head, body) = response.split_once("\r\n\r\n").expect("header block");
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    let json = serde_json::from_str(body.trim_end()).expect("JSON body");
    (ja4, json)
}

/// The `client` object the server must report for `ja4` and a `User-Agent` of `agent`.
fn expected(ja4: &Ja4, agent: Option<AgentFamily>) -> Value {
    let found = known::lookup(ja4);
    let (kind, consistent) = match (found, agent) {
        (Match::Exact(client), Some(agent)) => ("exact", Some(client.agrees_with(agent))),
        (Match::Exact(_), None) => ("exact", None),
        (Match::Ciphers(_), _) => ("ciphers", None),
        (Match::Unknown, _) => ("none", None),
    };
    let client = found.client();
    json!({
        "match": kind,
        "family": client.map(Client::family),
        "version": client.map(Client::version),
        "library": client.and_then(Client::library),
        "source": client.map(Client::source),
        "user_agent_family": agent.map_or("unknown", AgentFamily::name),
        "consistent": consistent,
    })
}

#[test]
fn api_all_and_clean_report_the_client_for_each_user_agent() {
    let agents = [
        (CHROME, Some(AgentFamily::Chrome)),
        ("curl/8.7.1", Some(AgentFamily::Curl)),
        ("Go-http-client/1.1", Some(AgentFamily::Go)),
        ("it/1", None),
        ("", None),
    ];
    for path in ["/api/all", "/api/clean"] {
        for (user_agent, family) in agents {
            let (_runtime, addr, roots) = start();
            let (ja4, json) = get(addr, roots, path, user_agent);
            assert_eq!(
                json["client"],
                expected(&ja4, family),
                "{path} with User-Agent {user_agent:?}"
            );
            let keys: Vec<&str> = json
                .as_object()
                .expect("object")
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                keys[keys.len() - 2..],
                ["client", "audit"],
                "{path}: `client` and `audit` are appended after the existing fields"
            );
            assert!(json["audit"]["score"].is_u64(), "{path}: {}", json["audit"]);
        }
    }
}

#[test]
fn the_test_client_is_recognized_as_rustls() {
    // The dataset holds this workspace's rustls with ALPN http/1.1, which is what `get` sends.
    // A rustls upgrade that changes the ClientHello turns this into a cipher match or none;
    // then recapture the rustls entries of corpus/clients.jsonl.
    let (_runtime, addr, roots) = start();
    let (ja4, json) = get(addr, roots, "/api/all", CHROME);
    let client = &json["client"];
    assert_eq!(client["match"], "exact", "{}", ja4.hashed());
    assert_eq!(client["family"], "rustls");
    assert_eq!(client["user_agent_family"], "Chrome");
    assert_eq!(client["consistent"], false);
}

#[test]
fn api_tls_keeps_its_layout() {
    let (_runtime, addr, roots) = start();
    let (_, json) = get(addr, roots, "/api/tls", "curl/8.7.1");
    assert!(json.get("client").is_none(), "{json}");
}
