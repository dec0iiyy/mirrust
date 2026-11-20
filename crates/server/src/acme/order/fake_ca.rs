//! An in-process look-alike of an ACME CA (RFC 8555), for testing `order.rs` end to end without
//! the network: the client's HTTP layer is replaced by [`Http`], which answers each request from
//! memory. Nothing here talks to Let's Encrypt or to any socket except the mirrust server that
//! is under test.
//!
//! What it checks, as a real CA does: the JWS envelope (a fresh single-use nonce, the `url`
//! header equal to the request URL, `jwk` for newAccount and `kid` for the rest, `ES256`),
//! `termsOfServiceAgreed`, `mailto:` contacts, that a challenge is answered only when its
//! authorization is pending, that finalize comes only when the order is `ready` and with a CSR
//! whose names are exactly the order's, and then, for TLS-ALPN-01, that the challenge
//! certificate is what RFC 8737 section 3 and Boulder's validator (`va/tlsalpn.go`) demand,
//! obtained by connecting to the mirrust server with ALPN `acme-tls/1` and the name as SNI.
//!
//! What it does not check: the JWS signatures, rate limits, CAA, multi-perspective validation,
//! IPv6, or anything that depends on how the real service behaves.

use std::collections::HashSet;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use bytes::Bytes;
use http_body::Body as _;
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, IsCa, Issuer, KeyPair,
    SanType, date_time_ymd,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer as _, X509Certificate};

use super::*;
use crate::{Config, serve, tls_config_with_resolver};

/// Makes the HTTP client an account talks through.
pub(super) type HttpFactory = Arc<dyn Fn() -> Box<dyn HttpClient> + Send + Sync>;

/// The host the URLs of the fake CA carry; nothing is ever resolved or connected.
const BASE: &str = "https://acme.fake.test";
const ACME_IDENTIFIER_OID: &str = "1.3.6.1.5.5.7.1.31";
const CHALLENGE_TYPES: [&str; 3] = ["http-01", "dns-01", "tls-alpn-01"];
const TLS_ALPN_INDEX: usize = 2;

/// What the fake does when a challenge is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Validation {
    /// Validates as RFC 8737 and Boulder do.
    Real,
    /// Marks the challenge invalid with this detail, without connecting.
    Reject(String),
    /// Never finishes.
    Hang,
}

#[derive(Debug)]
struct AccountRecord {
    thumbprint: String,
    contact: Vec<String>,
    terms_agreed: bool,
}

#[derive(Debug)]
struct AuthzRecord {
    name: String,
    tokens: [String; 3],
    /// Status of the TLS-ALPN-01 challenge; the others never leave `pending`.
    challenge: &'static str,
    error: Option<Value>,
}

impl AuthzRecord {
    /// An authorization is valid or invalid with its one answered challenge, else pending.
    fn status(&self) -> &'static str {
        match self.challenge {
            "valid" => "valid",
            "invalid" => "invalid",
            _ => "pending",
        }
    }
}

#[derive(Debug)]
struct OrderRecord {
    names: Vec<String>,
    authzs: Vec<usize>,
    finalized: bool,
    /// Polls of a finalized order that still say `processing`.
    processing_polls: u32,
    chain_pem: Option<String>,
}

#[derive(Debug)]
struct State {
    nonces: HashSet<String>,
    counter: u64,
    accounts: Vec<AccountRecord>,
    authzs: Vec<AuthzRecord>,
    orders: Vec<OrderRecord>,
    /// One word per request that changed something, in order, for the tests to read.
    log: Vec<&'static str>,
    bad_nonces_to_send: u32,
    validation: Validation,
    /// A challenge other than TLS-ALPN-01 was answered.
    wrong_challenge_answered: bool,
    /// The years the certificates it issues are valid from and until.
    years: (i32, i32),
}

struct Shared {
    state: Mutex<State>,
    /// The mirrust server whose port 443 stands in for the one the CA connects to.
    server: SocketAddr,
    issuer: Issuer<'static, KeyPair>,
    ca_pem: String,
}

/// A fake CA, cheap to clone.
#[derive(Clone)]
pub(super) struct FakeCa(Arc<Shared>);

/// What a handler answers.
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl FakeCa {
    /// A CA that validates by connecting to `server`.
    pub(super) fn new(server: SocketAddr) -> Self {
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2090, 1, 1);
        let key = KeyPair::generate().expect("key");
        let ca_pem = params.self_signed(&key).expect("ca certificate").pem();
        Self(Arc::new(Shared {
            state: Mutex::new(State {
                nonces: HashSet::new(),
                counter: 0,
                accounts: Vec::new(),
                authzs: Vec::new(),
                orders: Vec::new(),
                log: Vec::new(),
                bad_nonces_to_send: 0,
                validation: Validation::Real,
                wrong_challenge_answered: false,
                years: (2020, 2090),
            }),
            server,
            issuer: Issuer::new(params, key),
            ca_pem,
        }))
    }

    pub(super) fn factory(&self) -> HttpFactory {
        let ca = self.clone();
        Arc::new(move || Box::new(Http(ca.clone())) as Box<dyn HttpClient>)
    }

    /// The CA certificate, PEM.
    pub(super) fn ca_pem(&self) -> &str {
        &self.0.ca_pem
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.state.lock().expect("lock poisoned")
    }

    pub(super) fn set_validation(&self, validation: Validation) {
        self.state().validation = validation;
    }

    /// Issues certificates that are valid from January 1st of `from` until `until`.
    pub(super) fn set_certificate_years(&self, from: i32, until: i32) {
        self.state().years = (from, until);
    }

    /// The next `count` requests are answered `badNonce`.
    pub(super) fn send_bad_nonces(&self, count: u32) {
        self.state().bad_nonces_to_send = count;
    }

    pub(super) fn log(&self) -> Vec<&'static str> {
        self.state().log.clone()
    }

    pub(super) fn contacts(&self) -> Vec<Vec<String>> {
        let state = self.state();
        state
            .accounts
            .iter()
            .map(|account| account.contact.clone())
            .collect()
    }

    pub(super) fn terms_agreed(&self) -> bool {
        self.state()
            .accounts
            .iter()
            .all(|account| account.terms_agreed)
    }

    pub(super) fn wrong_challenge_answered(&self) -> bool {
        self.state().wrong_challenge_answered
    }

    fn handle(&self, method: &str, path: &str, body: &[u8]) -> Reply {
        let mut state = self.state();
        match (method, path) {
            ("GET", "/directory") => Reply::json(
                200,
                &json!({
                    "newNonce": format!("{BASE}/new-nonce"),
                    "newAccount": format!("{BASE}/new-acct"),
                    "newOrder": format!("{BASE}/new-order"),
                    "revokeCert": format!("{BASE}/revoke"),
                    "keyChange": format!("{BASE}/key-change"),
                    "meta": {"termsOfService": "https://example.test/terms.pdf"},
                }),
            ),
            ("HEAD" | "GET", "/new-nonce") => Reply::empty(200).with_nonce(&mut state),
            ("POST", _) => self.post(&mut state, path, body),
            _ => Reply::problem(&mut state, 404, "malformed", "no such resource"),
        }
    }

    /// A POST: checks the JWS envelope, then routes.
    fn post(&self, state: &mut State, path: &str, body: &[u8]) -> Reply {
        let envelope: Value = serde_json::from_slice(body).expect("a JWS in flattened JSON");
        let part = |name: &str| -> Vec<u8> {
            let text = envelope[name].as_str().expect("JWS member");
            BASE64_URL_SAFE_NO_PAD.decode(text).expect("base64url")
        };
        let protected: Value = serde_json::from_slice(&part("protected")).expect("protected");
        let payload = part("payload");

        if state.bad_nonces_to_send > 0 {
            state.bad_nonces_to_send -= 1;
            return Reply::problem(
                state,
                400,
                "badNonce",
                "JWS has an invalid anti-replay nonce",
            );
        }
        let nonce = protected["nonce"].as_str().unwrap_or_default();
        if !state.nonces.remove(nonce) {
            return Reply::problem(state, 400, "badNonce", "JWS has an unknown nonce");
        }
        if protected["url"] != format!("{BASE}{path}") {
            return Reply::problem(state, 400, "malformed", "JWS url differs from the request");
        }
        if protected["alg"] != "ES256" {
            return Reply::problem(state, 400, "badSignatureAlgorithm", "use ES256");
        }
        let jwk = protected.get("jwk");
        let key_id = protected["kid"].as_str();
        if jwk.is_some() == key_id.is_some() {
            return Reply::problem(state, 400, "malformed", "exactly one of jwk and kid");
        }
        let payload_text = String::from_utf8(payload).expect("payload is UTF-8");

        if path == "/new-acct" {
            let Some(jwk) = jwk else {
                return Reply::problem(state, 400, "malformed", "newAccount needs a jwk");
            };
            return Self::new_account(state, jwk, &payload_text);
        }
        if key_id != Some(&format!("{BASE}/acct/1")) || state.accounts.is_empty() {
            return Reply::problem(state, 400, "accountDoesNotExist", "unknown account");
        }
        let (resource, index) = path
            .trim_start_matches('/')
            .split_once('/')
            .map_or((path.trim_start_matches('/'), 0), |(resource, index)| {
                (resource, index.parse().unwrap_or(usize::MAX))
            });
        match resource {
            "new-order" => Self::new_order(state, &payload_text),
            "authz" => Self::authorization(state, index),
            "chall" => self.answer_challenge(state, index, &payload_text),
            "order" => Self::order(state, index),
            "finalize" => self.finalize(state, index, &payload_text),
            "cert" => Self::certificate(state, index),
            _ => Reply::problem(state, 404, "malformed", "no such resource"),
        }
    }

    fn new_account(state: &mut State, jwk: &Value, payload: &str) -> Reply {
        let request: Value = serde_json::from_str(payload).expect("newAccount payload");
        let agreed = request["termsOfServiceAgreed"].as_bool() == Some(true);
        if !agreed {
            return Reply::problem(
                state,
                403,
                "userActionRequired",
                "you must agree to the terms of service",
            );
        }
        let contact: Vec<String> = request["contact"]
            .as_array()
            .map(|list| {
                list.iter()
                    .map(|entry| entry.as_str().unwrap_or_default().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        if contact.iter().any(|url| !url.starts_with("mailto:")) {
            return Reply::problem(state, 400, "unsupportedContact", "only mailto: contacts");
        }
        // RFC 7638: the members in lexicographic order, no white space.
        let canonical = json!({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]});
        let thumbprint = BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.to_string()));
        state.accounts.push(AccountRecord {
            thumbprint,
            contact: contact.clone(),
            terms_agreed: agreed,
        });
        state.log.push("new-account");
        Reply::json(201, &json!({"status": "valid", "contact": contact}))
            .with_header("Location", format!("{BASE}/acct/1"))
            .with_nonce(state)
    }

    fn new_order(state: &mut State, payload: &str) -> Reply {
        let request: Value = serde_json::from_str(payload).expect("newOrder payload");
        let mut names = Vec::new();
        for identifier in request["identifiers"].as_array().expect("identifiers") {
            if identifier["type"] != "dns" {
                return Reply::problem(state, 400, "unsupportedIdentifier", "dns only");
            }
            let name = identifier["value"].as_str().expect("value").to_owned();
            if name != name.to_ascii_lowercase() || name.ends_with('.') {
                return Reply::problem(state, 400, "rejectedIdentifier", "not canonical");
            }
            names.push(name);
        }
        if names.is_empty() {
            return Reply::problem(state, 400, "malformed", "no identifiers");
        }
        let mut authzs = Vec::new();
        for name in &names {
            let tokens = [(); 3].map(|()| {
                state.counter += 1;
                BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(format!("token {}", state.counter)))
            });
            authzs.push(state.authzs.len());
            state.authzs.push(AuthzRecord {
                name: name.clone(),
                tokens,
                challenge: "pending",
                error: None,
            });
        }
        state.orders.push(OrderRecord {
            names,
            authzs,
            finalized: false,
            processing_polls: 1,
            chain_pem: None,
        });
        state.log.push("new-order");
        let index = state.orders.len() - 1;
        let body = order_json(state, index);
        Reply::json(201, &body)
            .with_header("Location", format!("{BASE}/order/{index}"))
            .with_nonce(state)
    }

    fn authorization(state: &mut State, index: usize) -> Reply {
        if index >= state.authzs.len() {
            return Reply::problem(state, 404, "malformed", "no such authorization");
        }
        let body = authz_json(&state.authzs[index], index);
        Reply::json(200, &body).with_nonce(state)
    }

    fn order(state: &mut State, index: usize) -> Reply {
        if index >= state.orders.len() {
            return Reply::problem(state, 404, "malformed", "no such order");
        }
        let order = &mut state.orders[index];
        if order.finalized && order.processing_polls > 0 {
            order.processing_polls -= 1;
        }
        let body = order_json(state, index);
        Reply::json(200, &body).with_nonce(state)
    }

    /// The POST that says the client is ready for validation: `challenge` is the id of the
    /// authorization times three plus the type index.
    fn answer_challenge(&self, state: &mut State, id: usize, payload: &str) -> Reply {
        let (authz, kind) = (id / 3, id % 3);
        if authz >= state.authzs.len() {
            return Reply::problem(state, 404, "malformed", "no such challenge");
        }
        if payload != "{}" {
            return Reply::problem(state, 400, "malformed", "a challenge response is {}");
        }
        if kind != TLS_ALPN_INDEX {
            state.wrong_challenge_answered = true;
        }
        if state.authzs[authz].challenge != "pending" {
            return Reply::problem(state, 400, "malformed", "the challenge is not pending");
        }
        state.authzs[authz].challenge = "processing";
        state.log.push("challenge");
        let record = &state.authzs[authz];
        let name = record.name.clone();
        let thumbprint = state.accounts[0].thumbprint.clone();
        let key_authorization = format!("{}.{thumbprint}", record.tokens[TLS_ALPN_INDEX]);
        let validation = state.validation.clone();
        let reply = Reply::json(
            200,
            &challenge_json(&state.authzs[authz], authz, TLS_ALPN_INDEX),
        )
        .with_nonce(state);

        let ca = self.clone();
        tokio::spawn(async move {
            let outcome = match validation {
                Validation::Real => validate(ca.0.server, &name, &key_authorization).await,
                Validation::Reject(detail) => Err(detail),
                Validation::Hang => std::future::pending().await,
            };
            let mut state = ca.state();
            let record = &mut state.authzs[authz];
            match outcome {
                Ok(()) => record.challenge = "valid",
                Err(detail) => {
                    record.challenge = "invalid";
                    record.error = Some(json!({
                        "type": "urn:ietf:params:acme:error:unauthorized",
                        "detail": detail,
                        "status": 403,
                    }));
                }
            }
        });
        reply
    }

    fn finalize(&self, state: &mut State, index: usize, payload: &str) -> Reply {
        if index >= state.orders.len() {
            return Reply::problem(state, 404, "malformed", "no such order");
        }
        let status = order_status(state, index);
        if status != "ready" {
            return Reply::problem(state, 403, "orderNotReady", &format!("order is {status}"));
        }
        let request: Value = serde_json::from_str(payload).expect("finalize payload");
        let csr_der = BASE64_URL_SAFE_NO_PAD
            .decode(request["csr"].as_str().expect("csr"))
            .expect("base64url csr");
        let csr =
            CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(csr_der));
        let mut csr = match csr {
            Ok(csr) => csr,
            Err(error) => {
                return Reply::problem(state, 400, "badCSR", &format!("unreadable CSR: {error}"));
            }
        };
        let mut csr_names: Vec<String> = csr
            .params
            .subject_alt_names
            .iter()
            .map(|san| match san {
                SanType::DnsName(name) => name.as_str().to_owned(),
                other => format!("{other:?}"),
            })
            .collect();
        csr_names.sort();
        let mut order_names = state.orders[index].names.clone();
        order_names.sort();
        if csr_names != order_names {
            return Reply::problem(
                state,
                400,
                "badCSR",
                &format!("CSR names {csr_names:?} differ from the order's {order_names:?}"),
            );
        }
        let (from, until) = state.years;
        csr.params.not_before = date_time_ymd(from, 1, 1);
        csr.params.not_after = date_time_ymd(until, 1, 1);
        let leaf = csr
            .signed_by(&self.0.issuer)
            .expect("issue the certificate");
        let order = &mut state.orders[index];
        order.finalized = true;
        // Leaf first, as RFC 8555 section 7.4.2 and the CA's own chain order it.
        order.chain_pem = Some(format!("{}{}", leaf.pem(), self.0.ca_pem));
        state.log.push("finalize");
        let body = order_json(state, index);
        Reply::json(200, &body)
            .with_header("Location", format!("{BASE}/order/{index}"))
            .with_nonce(state)
    }

    fn certificate(state: &mut State, index: usize) -> Reply {
        let Some(pem) = state.orders.get(index).and_then(|o| o.chain_pem.clone()) else {
            return Reply::problem(state, 404, "malformed", "no certificate");
        };
        state.log.push("certificate");
        Reply {
            status: 200,
            headers: vec![(
                "Content-Type",
                "application/pem-certificate-chain".to_owned(),
            )],
            body: pem.into_bytes(),
        }
        .with_nonce(state)
    }
}

/// The order status as RFC 8555 section 7.1.6 derives it.
fn order_status(state: &State, index: usize) -> &'static str {
    let order = &state.orders[index];
    if order.finalized {
        return if order.processing_polls > 0 {
            "processing"
        } else {
            "valid"
        };
    }
    let statuses: Vec<&str> = order
        .authzs
        .iter()
        .map(|&a| state.authzs[a].status())
        .collect();
    if statuses.contains(&"invalid") {
        "invalid"
    } else if statuses.iter().all(|&status| status == "valid") {
        "ready"
    } else {
        "pending"
    }
}

fn order_json(state: &State, index: usize) -> Value {
    let order = &state.orders[index];
    let status = order_status(state, index);
    let mut body = json!({
        "status": status,
        "identifiers": order.names.iter().map(|n| json!({"type": "dns", "value": n})).collect::<Vec<_>>(),
        "authorizations": order.authzs.iter().map(|a| format!("{BASE}/authz/{a}")).collect::<Vec<_>>(),
        "finalize": format!("{BASE}/finalize/{index}"),
    });
    if status == "valid" {
        body["certificate"] = json!(format!("{BASE}/cert/{index}"));
    }
    body
}

fn challenge_json(record: &AuthzRecord, authz: usize, kind: usize) -> Value {
    let status = if kind == TLS_ALPN_INDEX {
        record.challenge
    } else {
        "pending"
    };
    let mut body = json!({
        "type": CHALLENGE_TYPES[kind],
        "url": format!("{BASE}/chall/{}", authz * 3 + kind),
        "status": status,
        "token": record.tokens[kind],
    });
    if let (TLS_ALPN_INDEX, Some(error)) = (kind, &record.error) {
        body["error"] = error.clone();
    }
    body
}

fn authz_json(record: &AuthzRecord, index: usize) -> Value {
    json!({
        "status": record.status(),
        "identifier": {"type": "dns", "value": record.name},
        "challenges": (0..3).map(|kind| challenge_json(record, index, kind)).collect::<Vec<_>>(),
    })
}

impl Reply {
    fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn json(status: u16, body: &Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type", "application/json".to_owned())],
            body: body.to_string().into_bytes(),
        }
    }

    /// An RFC 8555 section 6.7 problem document, with a fresh nonce as section 6.5 asks.
    fn problem(state: &mut State, status: u16, kind: &str, detail: &str) -> Self {
        let body = json!({
            "type": format!("urn:ietf:params:acme:error:{kind}"),
            "detail": detail,
            "status": status,
        });
        let mut reply = Self::json(status, &body);
        reply.headers[0].1 = "application/problem+json".to_owned();
        reply.with_nonce(state)
    }

    fn with_header(mut self, name: &'static str, value: String) -> Self {
        self.headers.push((name, value));
        self
    }

    fn with_nonce(self, state: &mut State) -> Self {
        state.counter += 1;
        let nonce =
            BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(format!("nonce {}", state.counter)));
        state.nonces.insert(nonce.clone());
        self.with_header("Replay-Nonce", nonce)
    }

    fn into_response(self) -> BytesResponse {
        let mut builder = http::Response::builder().status(self.status);
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        BytesResponse::from(
            builder
                .body(BodyWrapper::from(self.body))
                .expect("response"),
        )
    }
}

/// The HTTP client of the account: routes each request to the fake CA.
struct Http(FakeCa);

impl HttpClient for Http {
    fn request(
        &self,
        request: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let ca = self.0.clone();
        Box::pin(async move {
            let (parts, mut body) = request.into_parts();
            // The directory is asked for at the authority's real URL, and answered here like
            // everything else; after that the client must use the URLs the directory gave.
            let directory = CertificateAuthority::LetsEncryptStaging.directory_url();
            assert!(
                parts.uri.to_string().starts_with(BASE) || parts.uri == directory,
                "unexpected URL {}",
                parts.uri
            );
            let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
            let bytes = frame
                .and_then(Result::ok)
                .and_then(|frame| frame.into_data().ok())
                .unwrap_or_default();
            let reply = ca.handle(parts.method.as_str(), parts.uri.path(), &bytes);
            if parts.uri.path().starts_with("/chall/") {
                // The CA starts validating at once; the answer reaches the client later, as
                // over a real network, so a client that installs its challenge response only
                // after the answer is caught.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(reply.into_response())
        })
    }
}

/// A server certificate verifier that accepts anything: the validator inspects the certificate
/// itself.
#[derive(Debug)]
struct AcceptAnything;

impl ServerCertVerifier for AcceptAnything {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// TLS-ALPN-01 validation as RFC 8737 section 3 describes it: connect with SNI `name` and ALPN
/// `acme-tls/1` only, expect that protocol to be negotiated, and check the certificate.
async fn validate(server: SocketAddr, name: &str, key_authorization: &str) -> Result<(), String> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnything))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let server_name = ServerName::try_from(name.to_owned()).map_err(|e| e.to_string())?;
    let connect = async {
        let socket = TcpStream::connect(server)
            .await
            .map_err(|e| e.to_string())?;
        TlsConnector::from(Arc::new(config))
            .connect(server_name, socket)
            .await
            .map_err(|e| format!("TLS handshake: {e}"))
    };
    let tls = tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .map_err(|_| "timeout during the handshake".to_owned())??;
    let (_, connection) = tls.get_ref();
    if connection.alpn_protocol() != Some(b"acme-tls/1") {
        return Err("cannot negotiate ALPN protocol acme-tls/1".to_owned());
    }
    let certificate = connection
        .peer_certificates()
        .and_then(<[_]>::first)
        .ok_or("no certificate presented")?;
    check_challenge_certificate(certificate, name, key_authorization)
}

/// What Boulder's `validateTLSALPN01` requires of the certificate.
fn check_challenge_certificate(
    der: &CertificateDer<'_>,
    name: &str,
    key_authorization: &str,
) -> Result<(), String> {
    let (_, cert) = X509Certificate::from_der(der.as_ref()).map_err(|e| e.to_string())?;
    if cert.subject().as_raw() != cert.issuer().as_raw() {
        return Err("not self-signed: subject and issuer differ".to_owned());
    }
    cert.verify_signature(None)
        .map_err(|e| format!("not self-signed: bad signature: {e}"))?;
    let mut seen = HashSet::new();
    for extension in cert.extensions() {
        if !seen.insert(extension.oid.to_id_string()) {
            return Err(format!("extension {} twice", extension.oid));
        }
    }
    let mut san_checked = false;
    let mut identifier_checked = false;
    for extension in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            match san.general_names.as_slice() {
                [GeneralName::DNSName(dns)] if dns.eq_ignore_ascii_case(name) => {}
                other => return Err(format!("unexpected identifiers: {other:?}")),
            }
            san_checked = true;
        }
        if extension.oid.to_id_string() == ACME_IDENTIFIER_OID {
            if !extension.critical {
                return Err("acmeIdentifier extension is not critical".to_owned());
            }
            let digest = Sha256::digest(key_authorization);
            // The extension value is the DER of an OCTET STRING holding the digest.
            let mut expected = vec![0x04, 0x20];
            expected.extend_from_slice(&digest);
            if extension.value != expected.as_slice() {
                return Err(format!(
                    "acmeIdentifier value {:02x?} is not the DER OCTET STRING of the key \
                     authorization's SHA-256 {:02x?}",
                    extension.value, expected
                ));
            }
            identifier_checked = true;
        }
    }
    if !san_checked {
        return Err("no subjectAltName".to_owned());
    }
    if !identifier_checked {
        return Err("no acmeIdentifier extension".to_owned());
    }
    Ok(())
}

/// A mirrust server on loopback with the ACME pieces, and a client whose CA is the fake.
struct Harness {
    client: Client,
    ca: FakeCa,
    addr: SocketAddr,
    _dir: TempDir,
}

/// A directory removed when dropped.
struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Harness {
    async fn new(test: &str, names: &[&str]) -> Self {
        let dir =
            std::env::temp_dir().join(format!("mirrust-fake-ca-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let certs = Arc::new(CurrentCert::new());
        let challenges = AcmeChallenges::new();
        let tls = Arc::new(tls_config_with_resolver(
            Arc::clone(&certs) as Arc<dyn rustls::server::ResolvesServerCert>
        ));
        let config = Config {
            challenges: Some(challenges.clone()),
            ..Config::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(serve(listener, tls, Arc::new(config)));

        let ca = FakeCa::new(addr);
        let authority = CertificateAuthority::LetsEncryptStaging;
        let client = Client {
            settings: Settings {
                names: names.iter().map(|&n| n.to_owned()).collect(),
                email: Some("ops@example.com".to_owned()),
                authority,
            },
            cache: CertCache::open(&dir, authority).expect("cache"),
            certs,
            challenges,
            http: Some(ca.factory()),
        };
        Self {
            client,
            ca,
            addr,
            _dir: TempDir(dir),
        }
    }

    /// The certificate chain a browser-like client gets for `name`, checked against the CA.
    async fn visit(&self, name: &str) -> Vec<CertificateDer<'static>> {
        let mut roots = rustls::RootCertStore::empty();
        let ca = CertificateDer::from_pem_slice(self.ca.ca_pem().as_bytes()).expect("ca pem");
        roots.add(ca).expect("root");
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let socket = TcpStream::connect(self.addr).await.expect("connect");
        let server_name = ServerName::try_from(name.to_owned()).expect("name");
        let tls = TlsConnector::from(Arc::new(config))
            .connect(server_name, socket)
            .await
            .expect("a client that trusts the CA accepts the issued certificate");
        let (_, connection) = tls.get_ref();
        connection
            .peer_certificates()
            .expect("certificates")
            .to_vec()
    }
}

use rustls::pki_types::pem::PemObject as _;

#[tokio::test]
async fn a_certificate_for_two_names_is_issued_through_the_real_accept_path() {
    let harness = Harness::new("issue", &["a.mirror.test", "b.mirror.test"]).await;
    let validity = harness.client.attempt().await.expect("issued");
    assert!(validity.contains(SystemTime::now()));

    let log = harness.ca.log();
    assert_eq!(
        log,
        [
            "new-account",
            "new-order",
            "challenge",
            "challenge",
            "finalize",
            "certificate"
        ],
        "one challenge per name, then finalize"
    );
    assert!(
        !harness.ca.wrong_challenge_answered(),
        "only the tls-alpn-01 challenge may be answered"
    );
    assert!(harness.ca.terms_agreed(), "termsOfServiceAgreed");
    assert_eq!(harness.ca.contacts(), [["mailto:ops@example.com"]]);
    assert!(
        harness.client.challenges.is_empty(),
        "every challenge entry is removed when the attempt ends"
    );

    // The issued certificate is what a visitor gets, leaf first, and its key works (the
    // handshake signs with the key the CSR carried).
    let seen = harness.visit("a.mirror.test").await;
    assert_eq!(seen.len(), 2, "leaf and CA");
    let stored = harness
        .client
        .cache
        .certificate(&harness.client.settings.names)
        .expect("read")
        .expect("saved");
    let leaf = CertificateDer::from_pem_slice(stored.chain_pem.as_bytes()).expect("first pem");
    assert_eq!(seen[0], leaf, "the cached chain starts with the leaf");

    // A restart finds the certificate in the cache and a second run reuses the account.
    harness.client.certs.set(Arc::new(
        certified_key(&stored.chain_pem, &stored.key_pem).expect("cached key matches"),
    ));
    harness.client.attempt().await.expect("renewed");
    let log = harness.ca.log();
    assert_eq!(
        log.iter().filter(|&&entry| entry == "new-account").count(),
        1,
        "the saved account is used again: {log:?}"
    );
    assert_eq!(harness.ca.contacts().len(), 1);
}

#[tokio::test]
async fn a_rejected_validation_fails_the_attempt_with_the_cas_words_and_clears_the_entries() {
    let harness = Harness::new("reject", &["a.mirror.test"]).await;
    harness
        .ca
        .set_validation(Validation::Reject("connection refused".to_owned()));
    let error = harness.client.attempt().await.expect_err("rejected");
    let text = format!("{error:#}");
    assert!(text.contains("validation failed"), "{text}");
    assert!(text.contains("connection refused"), "{text}");
    assert!(!harness.client.certs.is_set());
    assert!(harness.client.challenges.is_empty());
    assert!(!harness.ca.log().contains(&"finalize"));
}

#[tokio::test]
async fn a_certificate_that_is_already_due_for_renewal_is_not_ordered_again_in_a_loop() {
    // A host clock that is far ahead of the CA's (or a CA that issues short certificates)
    // makes the new certificate look due at once; each success resets the backoff.
    let harness = Harness::new("loop", &["a.mirror.test"]).await;
    harness.ca.set_certificate_years(2020, 2021);
    let ca = harness.ca.clone();
    let run = harness.client.run(
        SystemTime::now(),
        true,
        Backoff::new(FIRST_RETRY, LONGEST_RETRY),
    );
    tokio::time::timeout(Duration::from_millis(2500), run)
        .await
        .expect_err("the task never ends");
    let orders = ca
        .log()
        .iter()
        .filter(|&&entry| entry == "new-order")
        .count();
    assert_eq!(orders, 1, "one order, then a wait: {:?}", ca.log());
}

#[tokio::test]
async fn a_bad_nonce_is_retried() {
    let harness = Harness::new("nonce", &["a.mirror.test"]).await;
    harness.ca.send_bad_nonces(2);
    harness
        .client
        .attempt()
        .await
        .expect("issued despite badNonce");
}

#[tokio::test]
async fn a_cancelled_attempt_removes_its_challenge_entries() {
    let harness = Harness::new("cancel", &["a.mirror.test"]).await;
    harness.ca.set_validation(Validation::Hang);
    let attempt = tokio::time::timeout(Duration::from_millis(500), harness.client.obtain()).await;
    assert!(
        attempt.is_err(),
        "the validation hangs, so the attempt times out"
    );
    assert!(
        harness.ca.log().contains(&"challenge"),
        "the CA had been told the challenge was ready"
    );
    assert!(harness.client.challenges.is_empty());
}

#[tokio::test]
async fn the_ca_sees_the_challenge_entry_installed_before_it_is_told_to_validate() {
    // With the entry absent the real validation fails its handshake; with the code's order of
    // steps it succeeds. Removing the entry first proves the validation depends on it.
    let harness = Harness::new("entry", &["a.mirror.test"]).await;
    let outcome = validate(harness.addr, "a.mirror.test", "token.thumbprint").await;
    assert!(outcome.is_err(), "no entry installed: {outcome:?}");
}

#[tokio::test]
async fn a_validation_that_offers_other_protocols_too_or_an_upper_case_name_is_answered() {
    let harness = Harness::new("alpn", &["a.mirror.test"]).await;
    let digest = Sha256::digest("token.thumbprint");
    let certified = challenge_certificate("a.mirror.test", &digest).expect("certificate");
    harness
        .client
        .challenges
        .insert("a.mirror.test", Arc::new(certified));
    for (name, protocols) in [
        ("A.Mirror.Test", vec![b"acme-tls/1".to_vec()]),
        (
            "a.mirror.test",
            vec![b"h2".to_vec(), b"acme-tls/1".to_vec()],
        ),
    ] {
        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnything))
            .with_no_client_auth();
        config.alpn_protocols = protocols;
        let socket = TcpStream::connect(harness.addr).await.expect("connect");
        let server_name = ServerName::try_from(name.to_owned()).expect("name");
        let tls = TlsConnector::from(Arc::new(config))
            .connect(server_name, socket)
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let (_, connection) = tls.get_ref();
        assert_eq!(
            connection.alpn_protocol(),
            Some(&b"acme-tls/1"[..]),
            "{name}"
        );
        let seen = &connection.peer_certificates().expect("certificate")[0];
        assert_eq!(
            check_challenge_certificate(seen, "a.mirror.test", "token.thumbprint"),
            Ok(())
        );
    }
}

#[test]
fn the_validator_rejects_the_challenge_certificates_it_should() {
    let digest = Sha256::digest("token.thumbprint");
    let good = challenge_certificate("a.mirror.test", &digest).expect("certificate");
    let der = &good.cert[0];
    assert_eq!(
        check_challenge_certificate(der, "a.mirror.test", "token.thumbprint"),
        Ok(())
    );
    assert_eq!(
        check_challenge_certificate(der, "A.Mirror.Test", "token.thumbprint"),
        Ok(())
    );
    assert!(check_challenge_certificate(der, "b.mirror.test", "token.thumbprint").is_err());
    assert!(check_challenge_certificate(der, "a.mirror.test", "other.thumbprint").is_err());
}
