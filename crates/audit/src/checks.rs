//! The individual checks. Each returns `None` when it does not apply to the connection.

use fingerprint::known::{AgentFamily, Client, Match, UserAgent};
use fingerprint::{ClientHello, Ja4, Transport, is_grease};

use crate::{Check, Input, Status, Syn};

const SUPPORTED_GROUPS: u16 = 10;
const COMPRESS_CERTIFICATE: u16 = 27;
const RECORD_SIZE_LIMIT: u16 = 28;
const DELEGATED_CREDENTIALS: u16 = 34;
const SUPPORTED_VERSIONS: u16 = 43;
/// `quic_transport_parameters`, final and draft codepoint.
const QUIC_TRANSPORT_PARAMETERS: u16 = 57;
const QUIC_TRANSPORT_PARAMETERS_DRAFT: u16 = 0xffa5;
/// `application_settings`, old and current codepoint.
const ALPS: [u16; 2] = [17513, 17613];

/// The most the header check takes off, however many headers are missing.
const HEADERS_MAX_PENALTY: u8 = 30;
/// An MSS this far below the Ethernet value is still an ordinary access line (`PPPoE`).
const MSS_SLACK: u16 = 8;

fn check(
    id: &'static str,
    title: &'static str,
    status: Status,
    penalty: u8,
    detail: String,
) -> Check {
    Check {
        id,
        status,
        title,
        detail,
        penalty,
    }
}

/// Browser engines, which is what a TLS stack and an HTTP/2 implementation belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Engine {
    Chromium,
    Gecko,
    WebKit,
}

fn engine(agent: UserAgent) -> Option<Engine> {
    match agent.family {
        AgentFamily::Chrome | AgentFamily::Edge => Some(Engine::Chromium),
        AgentFamily::Firefox => Some(Engine::Gecko),
        AgentFamily::Safari => Some(Engine::WebKit),
        _ => None,
    }
}

/// `Chrome 120-131`, or the family alone when the entry has no version.
fn named(client: &Client) -> String {
    match client.version() {
        "" => client.family().to_owned(),
        version => format!("{} {version}", client.family()),
    }
}

/// Whether the hello has the cipher list and the extensions of `client`, so that its JA4 can
/// differ only in the first part: SNI, ALPN or transport. A browser opened by IP address
/// sends no SNI and is still the same browser.
fn same_lists(hello: &ClientHello, client: &Client) -> bool {
    let ours = Ja4::new(hello, Transport::Tcp);
    let tail = |ja4: &str| ja4.split_once('_').map(|(_, lists)| lists.to_owned());
    tail(ours.hashed()).is_some_and(|lists| Some(lists) == tail(client.ja4()))
}

/// The matched client when the match is as good as exact: the whole JA4, or everything but
/// its first part.
fn identified(input: &Input<'_>) -> Option<&'static Client> {
    match input.known {
        Match::Exact(client) => Some(client),
        Match::Ciphers(client) if same_lists(input.hello, client) => Some(client),
        Match::Ciphers(_) | Match::Unknown => None,
    }
}

fn has_extension(hello: &ClientHello, kind: u16) -> bool {
    hello.extensions.iter().any(|e| e.kind == kind)
}

pub(crate) fn tls_known(input: &Input<'_>) -> Check {
    const ID: &str = "tls_known";
    const TITLE: &str = "TLS fingerprint against known clients";
    match input.known {
        Match::Exact(client) => check(
            ID,
            TITLE,
            Status::Pass,
            0,
            format!("Identical to {}", named(client)),
        ),
        Match::Ciphers(client) if same_lists(input.hello, client) => check(
            ID,
            TITLE,
            Status::Pass,
            0,
            format!(
                "Cipher list and extensions of {}; only SNI or ALPN differ",
                named(client)
            ),
        ),
        Match::Ciphers(client) => check(
            ID,
            TITLE,
            Status::Warn,
            5,
            format!(
                "Same cipher list as {}, different extensions: a modified, older or newer build",
                named(client)
            ),
        ),
        Match::Unknown => check(
            ID,
            TITLE,
            Status::Warn,
            10,
            "Matches no client in the dataset".to_owned(),
        ),
    }
}

pub(crate) fn ua_tls(input: &Input<'_>) -> Option<Check> {
    const ID: &str = "ua_tls";
    const TITLE: &str = "User-Agent against the TLS stack";
    if input.user_agent.is_empty() {
        return Some(check(
            ID,
            TITLE,
            Status::Warn,
            10,
            "No User-Agent header".to_owned(),
        ));
    }
    let (agent, client) = (input.agent?, input.known.client()?);
    Some(if client.agrees_with(agent.family) {
        check(
            ID,
            TITLE,
            Status::Pass,
            0,
            format!(
                "The User-Agent says {}, the TLS stack is {}",
                agent.family.name(),
                client.family()
            ),
        )
    } else {
        check(
            ID,
            TITLE,
            Status::Fail,
            if identified(input).is_some() { 40 } else { 25 },
            format!(
                "The User-Agent says {}, but the TLS stack is {}",
                agent.family.name(),
                named(client)
            ),
        )
    })
}

/// Without a dataset match, a claimed browser must at least have the traits of its engine.
pub(crate) fn tls_traits(input: &Input<'_>) -> Option<Check> {
    const ID: &str = "tls_traits";
    const TITLE: &str = "TLS traits of the claimed browser";
    if input.known != Match::Unknown {
        return None;
    }
    let agent = input.agent?;
    let engine = engine(agent)?;
    // Only Apple's TLS stack is known to send GREASE. WebKitGTK (GnuTLS or OpenSSL) and the old
    // Android browser also say `Safari/` and send none.
    if engine == Engine::WebKit && user_agent_os(input.user_agent) != Some(Os::Darwin) {
        return None;
    }
    let family = agent.family.name();
    let hello = input.hello;
    let grease = hello.cipher_suites.iter().any(|&c| is_grease(c));
    // Chrome sends no GREASE in the cipher suites of a QUIC ClientHello, and offers h3 only.
    let quic = has_extension(hello, QUIC_TRANSPORT_PARAMETERS)
        || has_extension(hello, QUIC_TRANSPORT_PARAMETERS_DRAFT);
    let alps = ALPS.iter().any(|&kind| has_extension(hello, kind));
    let offers_h2 = hello.alpn.iter().any(|name| name == b"h2");

    let mut wrong: Vec<&str> = Vec::new();
    match engine {
        Engine::Chromium => {
            if !grease && !quic {
                wrong.push("no GREASE values");
            }
            if !has_extension(hello, COMPRESS_CERTIFICATE) {
                wrong.push("no compress_certificate");
            }
            if offers_h2 && !alps {
                wrong.push("no application_settings");
            }
            if has_extension(hello, RECORD_SIZE_LIMIT) {
                wrong.push("record_size_limit, which Chrome does not send");
            }
        }
        Engine::Gecko => {
            if grease {
                wrong.push("GREASE values, which Firefox does not send");
            }
            if !has_extension(hello, RECORD_SIZE_LIMIT) {
                wrong.push("no record_size_limit");
            }
            if !has_extension(hello, DELEGATED_CREDENTIALS) {
                wrong.push("no delegated_credentials");
            }
            if alps {
                wrong.push("application_settings, which Firefox does not send");
            }
        }
        Engine::WebKit => {
            if !grease && !quic {
                wrong.push("no GREASE values");
            }
            if alps {
                wrong.push("application_settings, which Safari does not send");
            }
        }
    }
    Some(if wrong.is_empty() {
        check(
            ID,
            TITLE,
            Status::Pass,
            0,
            format!("Has the extensions {family} is known for"),
        )
    } else {
        check(
            ID,
            TITLE,
            Status::Fail,
            30,
            format!("Unlike {family}: {}", wrong.join("; ")),
        )
    })
}

pub(crate) fn ua_version(input: &Input<'_>) -> Option<Check> {
    let (agent, client) = (input.agent?, identified(input)?);
    let (major, (first, _)) = (agent.major?, client.version_range()?);
    if !client.agrees_with(agent.family) || major >= first {
        return None;
    }
    Some(check(
        "ua_version",
        "User-Agent version against the TLS fingerprint",
        Status::Warn,
        10,
        format!(
            "The User-Agent says version {major}; this TLS fingerprint is that of {}",
            named(client)
        ),
    ))
}

/// Protocol names of an ALPN-shaped list: a two-byte length, then one-byte-length names.
fn protocol_names(data: &[u8]) -> Vec<&[u8]> {
    let mut rest = data.get(2..).unwrap_or_default();
    let mut names = Vec::new();
    while let Some((&len, tail)) = rest.split_first() {
        let Some((name, tail)) = tail.split_at_checked(usize::from(len)) else {
            break;
        };
        names.push(name);
        rest = tail;
    }
    names
}

pub(crate) fn alps_alpn(input: &Input<'_>) -> Option<Check> {
    const ID: &str = "alps_alpn";
    const TITLE: &str = "application_settings against ALPN";
    let hello = input.hello;
    let alps = hello.extensions.iter().find(|e| ALPS.contains(&e.kind))?;
    let missing: Vec<String> = protocol_names(&alps.data)
        .into_iter()
        .filter(|name| !hello.alpn.iter().any(|offered| offered == name))
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect();
    Some(if missing.is_empty() {
        check(
            ID,
            TITLE,
            Status::Pass,
            0,
            "Every protocol in application_settings is also offered in ALPN".to_owned(),
        )
    } else {
        check(
            ID,
            TITLE,
            Status::Fail,
            30,
            format!(
                "application_settings names {}, which ALPN does not offer; no browser sends this, \
                 and it is visible to anyone on the path",
                missing.join(", ")
            ),
        )
    })
}

pub(crate) fn grease(input: &Input<'_>) -> Option<Check> {
    const ID: &str = "grease";
    const TITLE: &str = "GREASE across the ClientHello";
    let hello = input.hello;
    let mut places = vec![
        (
            "cipher suites",
            hello.cipher_suites.iter().any(|&c| is_grease(c)),
        ),
        (
            "extensions",
            hello.extensions.iter().any(|e| is_grease(e.kind)),
        ),
    ];
    if has_extension(hello, SUPPORTED_GROUPS) {
        places.push((
            "groups",
            hello.supported_groups.iter().any(|&g| is_grease(g)),
        ));
    }
    if has_extension(hello, SUPPORTED_VERSIONS) {
        places.push((
            "versions",
            hello.supported_versions.iter().any(|&v| is_grease(v)),
        ));
    }
    let names = |present: bool| -> Vec<&str> {
        places
            .iter()
            .filter(|(_, has)| *has == present)
            .map(|(name, _)| *name)
            .collect()
    };
    let (with, without) = (names(true), names(false));
    if with.is_empty() {
        return None;
    }
    Some(if without.is_empty() {
        check(
            ID,
            TITLE,
            Status::Pass,
            0,
            format!("GREASE values in {}", with.join(", ")),
        )
    } else {
        check(
            ID,
            TITLE,
            Status::Fail,
            20,
            format!(
                "GREASE values in {} but not in {}; clients that use GREASE put it in all of them",
                with.join(", "),
                without.join(", ")
            ),
        )
    })
}

pub(crate) fn http2(input: &Input<'_>) -> Option<Check> {
    const ID: &str = "http2";
    const TITLE: &str = "HTTP/2 fingerprint against the client";
    let akamai = input.akamai?;
    if let Some(client) = identified(input)
        && let Some(expected) = client.akamai()
    {
        return Some(if akamai == expected {
            check(
                ID,
                TITLE,
                Status::Pass,
                0,
                format!(
                    "Settings, window and header order are those of {}",
                    client.family()
                ),
            )
        } else {
            check(
                ID,
                TITLE,
                Status::Fail,
                30,
                format!(
                    "{} opens HTTP/2 with {expected}; this connection sent {akamai}",
                    named(client)
                ),
            )
        });
    }
    // Without a recorded fingerprint, the pseudo-header order of the claimed engine still holds.
    let agent = input.agent?;
    let family = agent.family.name();
    let expected = match engine(agent)? {
        Engine::Chromium => "m,a,s,p",
        Engine::Gecko => "m,p,a,s",
        Engine::WebKit => return None,
    };
    let order = akamai.rsplit('|').next()?;
    Some(if order == expected {
        check(
            ID,
            TITLE,
            Status::Pass,
            0,
            format!("Pseudo-header order {order}, as {family} sends"),
        )
    } else {
        check(
            ID,
            TITLE,
            Status::Fail,
            30,
            format!("{family} sends pseudo-headers as {expected}; this connection sent {order}"),
        )
    })
}

pub(crate) fn headers(input: &Input<'_>) -> Option<Check> {
    const ID: &str = "headers";
    const TITLE: &str = "Request headers of the claimed browser";
    /// First versions (major, minor) that send a `Sec-Fetch-*` header: Chrome 76, Firefox 90
    /// and Safari 16.4, as MDN's browser-compat-data has them for `Sec-Fetch-Site` and
    /// `Sec-Fetch-Mode`. Older browsers are not penalised.
    const SEC_FETCH_FROM: [(Engine, (u32, u32)); 3] = [
        (Engine::Chromium, (76, 0)),
        (Engine::Gecko, (90, 0)),
        (Engine::WebKit, (16, 4)),
    ];
    /// First Chromium version that sends `Sec-CH-UA`.
    const SEC_CH_UA_FROM: (u32, u32) = (89, 0);
    let (lines, agent) = (input.headers?, input.agent?);
    let engine = engine(agent)?;
    let family = agent.family.name();
    let has = |name: &str| {
        lines.iter().any(|line| {
            line.as_bytes()
                .get(..name.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(name.as_bytes()))
        })
    };
    // A User-Agent without a version counts as current, except for WebKit: iOS browsers that
    // are not Safari state none. A version without a minor number counts as its `.0`, the
    // oldest it can be, so that nothing is asked of a browser that may predate the header.
    let since = |from: (u32, u32)| {
        let version = agent.major.map(|major| (major, agent.minor.unwrap_or(0)));
        match engine {
            Engine::WebKit => version.is_some_and(|version| version >= from),
            Engine::Chromium | Engine::Gecko => version.is_none_or(|version| version >= from),
        }
    };
    let sends_sec_fetch = SEC_FETCH_FROM
        .iter()
        .any(|&(kind, from)| kind == engine && since(from));
    let sends_sec_ch_ua = engine == Engine::Chromium && since(SEC_CH_UA_FROM);

    let mut missing: Vec<&str> = Vec::new();
    let mut penalty: u8 = 0;
    // Chromium leaves `Sec-CH-UA` out when JavaScript is blocked for the site or the
    // User-Agent was overridden without client hints, so a real browser can lack it: a warning.
    if sends_sec_ch_ua && !has("sec-ch-ua:") {
        missing.push("sec-ch-ua");
        penalty += 10;
    }
    if sends_sec_fetch && !has("sec-fetch-") {
        missing.push("sec-fetch-*");
        penalty += 20;
    }
    if !has("accept-language:") {
        missing.push("accept-language");
        penalty += 10;
    }
    if !has("accept-encoding:") {
        missing.push("accept-encoding");
        penalty += 10;
    }
    Some(if missing.is_empty() {
        check(
            ID,
            TITLE,
            Status::Pass,
            0,
            format!("Has the headers {family} sends with every request"),
        )
    } else {
        check(
            ID,
            TITLE,
            if penalty >= 20 {
                Status::Fail
            } else {
                Status::Warn
            },
            penalty.min(HEADERS_MAX_PENALTY),
            format!(
                "{family} sends these with every request; missing here: {}",
                missing.join(", ")
            ),
        )
    })
}

/// Operating system families that differ in their TCP SYN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Os {
    Linux,
    Darwin,
    Windows,
}

impl Os {
    const fn name(self) -> &'static str {
        match self {
            Self::Linux => "Linux or Android",
            Self::Darwin => "macOS or iOS",
            Self::Windows => "Windows",
        }
    }
}

/// The system whose default SYN has this option layout.
fn tcp_stack(syn: &Syn<'_>) -> Option<Os> {
    match syn.option_order {
        "mss,sackOK,timestamp,nop,wscale" => Some(Os::Linux),
        "mss,nop,wscale,nop,nop,timestamp,sackOK,eol" => Some(Os::Darwin),
        "mss,nop,wscale,nop,nop,sackOK" => Some(Os::Windows),
        _ => None,
    }
}

/// The system a User-Agent names.
fn user_agent_os(user_agent: &str) -> Option<Os> {
    let has = |needle: &str| user_agent.contains(needle);
    if has("Windows NT") {
        Some(Os::Windows)
    } else if has("Android") {
        Some(Os::Linux)
    } else if has("iPhone") || has("iPad") || has("Macintosh") || has("Mac OS X") {
        Some(Os::Darwin)
    } else if has("Linux") || has("X11") || has("CrOS") {
        Some(Os::Linux)
    } else {
        None
    }
}

pub(crate) fn tcp_os(input: &Input<'_>) -> Option<Check> {
    const ID: &str = "tcp_os";
    const TITLE: &str = "TCP stack against the User-Agent";
    let Some(syn) = input.syn else {
        return Some(check(
            ID,
            TITLE,
            Status::Skip,
            0,
            "Not measured: this server did not capture the TCP SYN. Behind a proxy or VPN the \
             TCP stack is the exit's, the User-Agent the device's, and the two disagree here"
                .to_owned(),
        ));
    };
    let (stack, claimed) = (tcp_stack(&syn)?, user_agent_os(input.user_agent)?);
    Some(if stack == claimed {
        check(
            ID,
            TITLE,
            Status::Pass,
            0,
            format!(
                "TCP options are those of {}, as the User-Agent says",
                stack.name()
            ),
        )
    } else {
        check(
            ID,
            TITLE,
            Status::Fail,
            30,
            format!(
                "TCP options are those of {}, the User-Agent says {}: another machine opened \
                 this connection, as a proxy or VPN exit does",
                stack.name(),
                claimed.name()
            ),
        )
    })
}

pub(crate) fn tcp_mss(input: &Input<'_>) -> Option<Check> {
    const ID: &str = "tcp_mss";
    const TITLE: &str = "TCP segment size";
    let syn = input.syn?;
    if syn.mss == 0 {
        return None;
    }
    let ethernet: u16 = if syn.ipv6 { 1440 } else { 1460 };
    Some(if ethernet.saturating_sub(syn.mss) <= MSS_SLACK {
        check(
            ID,
            TITLE,
            Status::Pass,
            0,
            format!("MSS {}: a full-size path", syn.mss),
        )
    } else {
        check(
            ID,
            TITLE,
            Status::Warn,
            10,
            format!(
                "MSS {} is below {ethernet}: the path has a reduced MTU, as tunnels and some \
                 mobile networks do",
                syn.mss
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use fingerprint::Extension;
    use fingerprint::known;

    use super::*;
    use crate::{Verdict, audit};

    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/160.0.0.0 Safari/537.36";

    fn extension(kind: u16, data: &[u8]) -> Extension {
        Extension {
            kind,
            data: data.to_vec(),
        }
    }

    /// A hello with GREASE everywhere, ALPN `h2, http/1.1` and ALPS for `h2`.
    fn chrome_like() -> ClientHello {
        let mut hello = ClientHello::default();
        hello.cipher_suites = vec![0x0a0a, 0x1301, 0x1302];
        hello.supported_groups = vec![0x1a1a, 0x11ec, 0x001d];
        hello.supported_versions = vec![0x2a2a, 0x0304, 0x0303];
        hello.alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        hello.extensions = vec![
            extension(0x3a3a, &[]),
            extension(SUPPORTED_GROUPS, &[]),
            extension(SUPPORTED_VERSIONS, &[]),
            extension(COMPRESS_CERTIFICATE, &[]),
            extension(17613, b"\x00\x03\x02h2"),
        ];
        hello
    }

    /// A dataset entry of `family` that has an HTTP/2 fingerprint.
    fn with_http2(family: &str) -> &'static Client {
        known::clients()
            .iter()
            .find(|client| client.family() == family && client.akamai().is_some())
            .unwrap_or_else(|| panic!("no {family} entry with an HTTP/2 fingerprint"))
    }

    fn find<'a>(checks: &'a [Check], id: &str) -> &'a Check {
        checks
            .iter()
            .find(|check| check.id == id)
            .unwrap_or_else(|| panic!("no check {id}"))
    }

    #[test]
    fn a_real_chrome_scores_full() {
        let chrome = with_http2("Chrome");
        let hello = chrome_like();
        let headers = [
            "sec-ch-ua: \"Chromium\";v=\"160\"".to_owned(),
            "accept-encoding: gzip".to_owned(),
            "accept-language: en".to_owned(),
            "sec-fetch-mode: navigate".to_owned(),
        ];
        let mut input = Input::new(&hello, CHROME_UA);
        input.known = Match::Exact(chrome);
        input.akamai = chrome.akamai();
        input.headers = Some(&headers);
        let report = audit(&input);
        assert_eq!(report.score, 100, "{:#?}", report.checks);
        assert_eq!(report.verdict, Verdict::Consistent);
        assert_eq!(find(&report.checks, "tcp_os").status, Status::Skip);
    }

    #[test]
    fn a_chrome_user_agent_on_another_stack_is_inconsistent() {
        let curl = with_http2("curl");
        let hello = ClientHello::default();
        let mut input = Input::new(&hello, CHROME_UA);
        input.known = Match::Exact(curl);
        input.akamai = curl.akamai();
        input.headers = Some(&[]);
        let report = audit(&input);
        assert_eq!(find(&report.checks, "ua_tls").status, Status::Fail);
        assert_eq!(find(&report.checks, "headers").status, Status::Fail);
        assert_eq!(report.verdict, Verdict::Inconsistent);
    }

    #[test]
    fn chrome_tls_with_another_http2_fails() {
        let hello = chrome_like();
        let mut input = Input::new(&hello, CHROME_UA);
        input.known = Match::Exact(with_http2("Chrome"));
        input.akamai = with_http2("Go net/http").akamai();
        let found = http2(&input).expect("applies");
        assert_eq!(found.status, Status::Fail);
        assert!(found.detail.contains("Chrome"), "{}", found.detail);
    }

    #[test]
    fn alps_for_a_protocol_missing_from_alpn_fails() {
        let mut hello = chrome_like();
        hello.alpn = vec![b"http/1.1".to_vec()];
        let found = alps_alpn(&Input::new(&hello, CHROME_UA)).expect("applies");
        assert_eq!(found.status, Status::Fail);
        assert!(found.detail.contains("h2"), "{}", found.detail);

        let found = alps_alpn(&Input::new(&chrome_like(), CHROME_UA)).expect("applies");
        assert_eq!(found.status, Status::Pass);
        assert!(alps_alpn(&Input::new(&ClientHello::default(), "")).is_none());
    }

    #[test]
    fn partial_grease_fails_and_none_is_skipped() {
        let mut hello = chrome_like();
        hello.supported_groups = vec![0x001d];
        let found = grease(&Input::new(&hello, "")).expect("applies");
        assert_eq!(found.status, Status::Fail);
        assert!(found.detail.contains("not in groups"), "{}", found.detail);
        assert!(grease(&Input::new(&ClientHello::default(), "")).is_none());
    }

    #[test]
    fn an_unknown_stack_claiming_chrome_needs_its_traits() {
        let mut bare = ClientHello::default();
        bare.alpn = vec![b"h2".to_vec()];
        let found = tls_traits(&Input::new(&bare, CHROME_UA)).expect("applies");
        assert_eq!(found.status, Status::Fail);
        assert!(found.detail.contains("no GREASE"), "{}", found.detail);

        let hello = chrome_like();
        let found = tls_traits(&Input::new(&hello, CHROME_UA)).expect("applies");
        assert_eq!(found.status, Status::Pass);
        assert!(tls_traits(&Input::new(&hello, "curl/8.7.1")).is_none());
    }

    #[test]
    fn safari_traits_apply_to_apple_platforms_only() {
        const IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) \
            AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
        // WebKitGTK and WPE claim `Version/60.5`, and their TLS comes from GnuTLS or OpenSSL.
        const WEBKIT_GTK: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 \
            (KHTML, like Gecko) Version/60.5 Safari/605.1.15";
        let mut bare = ClientHello::default();
        bare.cipher_suites = vec![0x1301, 0xc02f];
        bare.alpn = vec![b"h2".to_vec()];
        let found = tls_traits(&Input::new(&bare, IPHONE)).expect("applies");
        assert_eq!(found.status, Status::Fail);
        assert!(found.detail.contains("no GREASE"), "{}", found.detail);
        assert!(tls_traits(&Input::new(&bare, WEBKIT_GTK)).is_none());
    }

    #[test]
    fn headers_that_a_real_chromium_can_lack_do_not_fail_it() {
        let headers = [
            "accept-encoding: gzip".to_owned(),
            "accept-language: en".to_owned(),
            "sec-fetch-mode: navigate".to_owned(),
        ];
        let hello = chrome_like();
        let mut input = Input::new(&hello, CHROME_UA);
        input.headers = Some(&headers);
        // JavaScript blocked for the site, or a custom User-Agent: no Sec-CH-UA.
        let found = self::headers(&input).expect("applies");
        assert_eq!(found.status, Status::Warn, "{}", found.detail);
        assert_eq!(found.penalty, 10);

        // Chrome 85 predates Sec-CH-UA, Firefox 80 predates Sec-Fetch-*.
        let old_chrome = CHROME_UA.replace("Chrome/160", "Chrome/85");
        let bare = [
            "accept-encoding: gzip".to_owned(),
            "accept-language: en".to_owned(),
        ];
        let mut input = Input::new(&hello, &old_chrome);
        input.headers = Some(&bare);
        let found = self::headers(&input).expect("applies");
        assert_eq!(found.status, Status::Fail, "{}", found.detail);
        assert!(found.detail.ends_with("sec-fetch-*"), "{}", found.detail);

        let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0";
        let mut input = Input::new(&hello, firefox);
        input.headers = Some(&bare);
        assert_eq!(self::headers(&input).expect("applies").status, Status::Pass);
        let firefox = firefox.replace("80.0", "133.0");
        let mut input = Input::new(&hello, &firefox);
        input.headers = Some(&bare);
        assert_eq!(self::headers(&input).expect("applies").status, Status::Fail);
    }

    #[test]
    fn safari_is_asked_for_sec_fetch_from_16_4_on() {
        let safari = |version: &str| {
            format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, \
                 like Gecko) Version/{version} Safari/605.1.15"
            )
        };
        let without = [
            "accept-encoding: gzip".to_owned(),
            "accept-language: en".to_owned(),
        ];
        let hello = ClientHello::default();
        let status = |version: &str| {
            let user_agent = safari(version);
            let mut input = Input::new(&hello, &user_agent);
            input.headers = Some(&without);
            self::headers(&input).expect("applies").status
        };
        // MDN browser-compat-data: Sec-Fetch-Site, -Mode and -Dest since Safari 16.4.
        for older in ["15.6", "16.0", "16.3.1", "16"] {
            assert_eq!(
                status(older),
                Status::Pass,
                "Safari {older} does not send them"
            );
        }
        for newer in ["16.4", "16.6", "17.0", "18.2"] {
            assert_eq!(status(newer), Status::Fail, "Safari {newer} sends them");
        }
    }

    #[test]
    fn a_quic_hello_without_grease_in_its_ciphers_is_not_a_mismatch() {
        let mut quic = ClientHello::default();
        quic.cipher_suites = vec![0x1301, 0x1302, 0x1303];
        quic.alpn = vec![b"h3".to_vec()];
        quic.extensions = vec![
            extension(QUIC_TRANSPORT_PARAMETERS, &[]),
            extension(COMPRESS_CERTIFICATE, &[]),
        ];
        let found = tls_traits(&Input::new(&quic, CHROME_UA)).expect("applies");
        assert_eq!(found.status, Status::Pass, "{}", found.detail);

        // The same hello with no QUIC extension is still missing its GREASE.
        quic.extensions.remove(0);
        let found = tls_traits(&Input::new(&quic, CHROME_UA)).expect("applies");
        assert_eq!(found.status, Status::Fail);
    }

    #[test]
    fn a_linux_syn_under_a_windows_user_agent_fails() {
        let hello = chrome_like();
        let mut input = Input::new(&hello, CHROME_UA);
        input.syn = Some(Syn {
            ttl: 52,
            mss: 1380,
            ipv6: false,
            option_order: "mss,sackOK,timestamp,nop,wscale",
        });
        assert_eq!(tcp_os(&input).expect("applies").status, Status::Fail);
        assert_eq!(tcp_mss(&input).expect("applies").status, Status::Warn);

        input.syn = Some(Syn {
            ttl: 116,
            mss: 1452,
            ipv6: false,
            option_order: "mss,nop,wscale,nop,nop,sackOK",
        });
        assert_eq!(tcp_os(&input).expect("applies").status, Status::Pass);
        assert_eq!(tcp_mss(&input).expect("applies").status, Status::Pass);
    }

    #[test]
    fn an_older_user_agent_than_the_fingerprint_warns() {
        let chrome = with_http2("Chrome");
        let (first, _) = chrome.version_range().expect("the entry has versions");
        let old = CHROME_UA.replace("Chrome/160", &format!("Chrome/{}", first - 1));
        let hello = chrome_like();
        let mut input = Input::new(&hello, &old);
        input.known = Match::Exact(chrome);
        assert_eq!(ua_version(&input).expect("applies").status, Status::Warn);
    }

    #[test]
    fn the_penalty_stays_out_of_the_json() {
        let report = audit(&Input::new(&ClientHello::default(), ""));
        let json = serde_json::to_value(&report).expect("serializes");
        assert_eq!(json["verdict"], "suspicious");
        assert!(json["checks"][0].get("penalty").is_none());
        assert_eq!(json["checks"][0]["status"], "warn");
    }
}
