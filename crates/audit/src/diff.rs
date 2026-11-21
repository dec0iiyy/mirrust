//! What separates a connection from the recorded reference of the browser its User-Agent
//! claims, layer by layer. Purely informational: the score does not use it.

use std::collections::BTreeSet;

use fingerprint::known::{self, AgentFamily, Client};
use fingerprint::{ClientHello, cipher_suite_name, extension_name, is_grease};
use serde::Serialize;

use crate::Input;
use crate::checks::{missing_headers, over_quic};

/// `server_name` and ALPN, which JA4 leaves out of its extension list, and so does the diff.
const SERVER_NAME: u16 = 0x0000;
const ALPN: u16 = 0x0010;
/// The current `application_settings` code point, which the IANA table this crate prints
/// names from does not list.
const APPLICATION_SETTINGS: u16 = 17613;

/// The connection against the closest recorded reference of the browser its User-Agent
/// claims. Present only when at least one layer differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diff {
    /// The dataset entry compared with.
    pub reference: Reference,
    /// Extensions and cipher suites, as sets.
    pub tls: TlsDiff,
    /// The HTTP/2 fingerprint; absent when the connection did not use HTTP/2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http2: Option<Http2Diff>,
    /// Request headers; absent when none is missing or the server did not see them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HeadersDiff>,
}

/// The dataset entry a [`Diff`] compares with: a recorded sample, not a specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reference {
    /// Family of the entry, such as `Chrome`.
    pub family: String,
    /// The version text of the entry, such as `150-158 (150.0.7871.127, ...)`.
    pub version: String,
    /// Where the sample came from, in a word.
    pub kind: SourceKind,
    /// Whether the same hello was also captured from a real browser, for an entry that
    /// comes from a profile or a signature.
    pub also_captured: bool,
    /// The entry's full source text.
    pub source: String,
}

/// The kind of sample a dataset entry was recorded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A uTLS imitation profile.
    UtlsProfile,
    /// A curl-impersonate signature file.
    CurlImpersonate,
    /// A hello captured from the real client.
    Captured,
}

impl SourceKind {
    /// The kind as the text report words it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UtlsProfile => "uTLS profile",
            Self::CurlImpersonate => "curl-impersonate signature",
            Self::Captured => "captured from the browser",
        }
    }

    fn of(source: &str) -> Self {
        if source.starts_with("uTLS") {
            Self::UtlsProfile
        } else if source.starts_with("curl-impersonate") {
            Self::CurlImpersonate
        } else {
            Self::Captured
        }
    }
}

/// A TLS code point with its IANA name, when it has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Code {
    /// The code point.
    pub id: u16,
    /// Its name; `None` when the registry table has none.
    pub name: Option<&'static str>,
}

/// TLS differences as sets, GREASE, SNI and ALPN left out as JA4 leaves them. The
/// reference's lists are stored sorted, so their order is not compared.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TlsDiff {
    /// Extensions the reference sends and this connection did not.
    pub missing_extensions: Vec<Code>,
    /// Extensions this connection sent and the reference does not.
    pub extra_extensions: Vec<Code>,
    /// Cipher suites the reference offers and this connection did not.
    pub missing_ciphers: Vec<Code>,
    /// Cipher suites this connection offered and the reference does not.
    pub extra_ciphers: Vec<Code>,
}

impl TlsDiff {
    /// Whether the sets are equal.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.missing_extensions.is_empty()
            && self.extra_extensions.is_empty()
            && self.missing_ciphers.is_empty()
            && self.extra_ciphers.is_empty()
    }
}

/// The connection's Akamai HTTP/2 fingerprint against the reference's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Http2Diff {
    /// This connection's fingerprint.
    pub yours: String,
    /// The reference's; `None` when the entry has no HTTP/2 capture.
    pub reference: Option<String>,
    /// Each part that differs; empty when the two are equal or there is no reference.
    pub differences: Vec<Difference>,
}

/// One HTTP/2 value that differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Difference {
    /// What differs: `SETTINGS INITIAL_WINDOW_SIZE (4)`, `settings order`, `WINDOW_UPDATE`,
    /// `PRIORITY` or `pseudo-header order`.
    pub field: String,
    /// This connection's value; `None` when it did not send it.
    pub yours: Option<String>,
    /// The reference's value; `None` when it does not send it.
    pub reference: Option<String>,
}

/// Request headers the claimed browser sends with every request that this one lacked. They
/// come from what the `headers` check expects of the claimed family, not from the reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeadersDiff {
    /// Header names; `sec-fetch-*` stands for the whole group.
    pub missing: Vec<&'static str>,
}

/// The dataset family whose entries stand for a claimed browser.
fn reference_family(agent: AgentFamily) -> Option<&'static str> {
    match agent {
        AgentFamily::Chrome | AgentFamily::Edge => Some("Chrome"),
        AgentFamily::Firefox => Some("Firefox"),
        AgentFamily::Safari => Some("Safari"),
        _ => None,
    }
}

/// The cipher suites and extensions of a hello as JA4 counts them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Lists {
    ciphers: BTreeSet<u16>,
    extensions: BTreeSet<u16>,
}

impl Lists {
    fn of_hello(hello: &ClientHello) -> Self {
        Self::new(
            hello.cipher_suites.iter().copied(),
            hello.extensions.iter().map(|extension| extension.kind),
        )
    }

    /// The lists of a `JA4_r` (`a_ciphers_extensions_algorithms`); `None` when it has fewer
    /// parts or a value is not hexadecimal.
    fn of_ja4_r(ja4_r: &str) -> Option<Self> {
        let mut parts = ja4_r.split('_');
        let (_, ciphers, extensions) = (parts.next()?, parts.next()?, parts.next()?);
        let hex = |list: &str| -> Option<Vec<u16>> {
            list.split(',')
                .filter(|value| !value.is_empty())
                .map(|value| u16::from_str_radix(value, 16).ok())
                .collect()
        };
        Some(Self::new(hex(ciphers)?, hex(extensions)?))
    }

    fn new(
        ciphers: impl IntoIterator<Item = u16>,
        extensions: impl IntoIterator<Item = u16>,
    ) -> Self {
        Self {
            ciphers: ciphers.into_iter().filter(|&id| !is_grease(id)).collect(),
            extensions: extensions
                .into_iter()
                .filter(|&id| !is_grease(id) && id != SERVER_NAME && id != ALPN)
                .collect(),
        }
    }

    /// Values in one set and not the other, counted over both lists.
    fn distance(&self, other: &Self) -> usize {
        self.ciphers.symmetric_difference(&other.ciphers).count()
            + self
                .extensions
                .symmetric_difference(&other.extensions)
                .count()
    }
}

/// How far a claimed major version is from an entry's range: 0 inside it. Without a claimed
/// version the newest entry counts as nearest, as a User-Agent without one counts as current.
fn version_distance(major: Option<u32>, client: &Client) -> u32 {
    match (major, client.version_range()) {
        (_, None) => u32::MAX,
        (Some(major), Some((first, _))) if major < first => first - major,
        (Some(major), Some((_, last))) => major.saturating_sub(last),
        (None, Some((_, last))) => u32::MAX - 1 - last.min(u32::MAX - 1),
    }
}

/// The entry of the claimed family to compare with, over the same transport. Entries with
/// the very lists of the connection come first, since the connection then has that browser's
/// TLS stack; then the entry whose version range is nearest the claimed version, and among
/// those the one whose lists are closest.
fn choose<'a>(
    candidates: &'a [Client],
    family: &str,
    quic: bool,
    major: Option<u32>,
    ours: &Lists,
) -> Option<(&'a Client, Lists)> {
    let transport = if quic { 'q' } else { 't' };
    let entries: Vec<(&Client, Lists)> = candidates
        .iter()
        .filter(|client| client.family() == family && client.ja4().starts_with(transport))
        .filter_map(|client| Some((client, Lists::of_ja4_r(client.ja4_r())?)))
        .collect();
    // `min_by_key` keeps the first of equal keys, so ties go to file order.
    let best = (0..entries.len()).min_by_key(|&index| {
        let (client, lists) = &entries[index];
        let distance = lists.distance(ours);
        (distance != 0, version_distance(major, client), distance)
    })?;
    entries.into_iter().nth(best)
}

fn codes(ids: impl Iterator<Item = u16>, name: fn(u16) -> Option<&'static str>) -> Vec<Code> {
    ids.map(|id| Code { id, name: name(id) }).collect()
}

fn extension_label(id: u16) -> Option<&'static str> {
    extension_name(id).or((id == APPLICATION_SETTINGS).then_some("application_settings"))
}

fn tls_diff(ours: &Lists, reference: &Lists) -> TlsDiff {
    TlsDiff {
        missing_extensions: codes(
            reference.extensions.difference(&ours.extensions).copied(),
            extension_label,
        ),
        extra_extensions: codes(
            ours.extensions.difference(&reference.extensions).copied(),
            extension_label,
        ),
        missing_ciphers: codes(
            reference.ciphers.difference(&ours.ciphers).copied(),
            cipher_suite_name,
        ),
        extra_ciphers: codes(
            ours.ciphers.difference(&reference.ciphers).copied(),
            cipher_suite_name,
        ),
    }
}

/// The four parts of an Akamai fingerprint, `SETTINGS|WINDOW_UPDATE|PRIORITY|order`.
struct Akamai<'a> {
    settings: Vec<(&'a str, &'a str)>,
    window_update: &'a str,
    priority: &'a str,
    order: &'a str,
}

impl<'a> Akamai<'a> {
    fn parse(text: &'a str) -> Option<Self> {
        let mut parts = text.split('|');
        let fingerprint = Self {
            settings: parts
                .next()?
                .split([';', ','])
                .filter(|setting| !setting.is_empty())
                .map(|setting| setting.split_once(':'))
                .collect::<Option<_>>()?,
            window_update: parts.next()?,
            priority: parts.next()?,
            order: parts.next()?,
        };
        parts.next().is_none().then_some(fingerprint)
    }

    /// The value of SETTINGS `id`, when it was sent.
    fn setting(&self, id: &str) -> Option<&'a str> {
        self.settings
            .iter()
            .find(|&&(other, _)| other == id)
            .map(|&(_, value)| value)
    }
}

/// The RFC 9113 name of a SETTINGS id, as the server's HTTP/2 report prints it.
fn setting_name(id: &str) -> String {
    let name = match id {
        "1" => "HEADER_TABLE_SIZE",
        "2" => "ENABLE_PUSH",
        "3" => "MAX_CONCURRENT_STREAMS",
        "4" => "INITIAL_WINDOW_SIZE",
        "5" => "MAX_FRAME_SIZE",
        "6" => "MAX_HEADER_LIST_SIZE",
        "8" => "ENABLE_CONNECT_PROTOCOL",
        "9" => "NO_RFC7540_PRIORITIES",
        _ => "UNKNOWN_SETTING",
    };
    format!("SETTINGS {name} ({id})")
}

fn http2_differences(yours: &str, reference: &str) -> Vec<Difference> {
    let difference = |field: &str, ours: Option<&str>, theirs: Option<&str>| Difference {
        field: field.to_owned(),
        yours: ours.map(str::to_owned),
        reference: theirs.map(str::to_owned),
    };
    let (Some(ours), Some(theirs)) = (Akamai::parse(yours), Akamai::parse(reference)) else {
        return vec![difference("fingerprint", Some(yours), Some(reference))];
    };
    let mut out = Vec::new();
    let ids: BTreeSet<&str> = ours
        .settings
        .iter()
        .chain(&theirs.settings)
        .map(|&(id, _)| id)
        .collect();
    for id in ids {
        let (mine, expected) = (ours.setting(id), theirs.setting(id));
        if mine != expected {
            out.push(difference(&setting_name(id), mine, expected));
        }
    }
    let order = |settings: &[(&str, &str)]| {
        settings
            .iter()
            .map(|&(id, _)| id)
            .collect::<Vec<_>>()
            .join(",")
    };
    let (mine, expected) = (order(&ours.settings), order(&theirs.settings));
    if out.is_empty() && mine != expected {
        out.push(difference("settings order", Some(&mine), Some(&expected)));
    }
    for (field, mine, expected) in [
        ("WINDOW_UPDATE", ours.window_update, theirs.window_update),
        ("PRIORITY", ours.priority, theirs.priority),
        ("pseudo-header order", ours.order, theirs.order),
    ] {
        if mine != expected {
            out.push(difference(field, Some(mine), Some(expected)));
        }
    }
    out
}

/// The diff of `input` against the closest reference of the browser its User-Agent claims;
/// `None` when it claims none the dataset has, or nothing differs.
pub(crate) fn diff(input: &Input<'_>) -> Option<Diff> {
    diff_against(input, known::clients())
}

fn diff_against(input: &Input<'_>, candidates: &[Client]) -> Option<Diff> {
    let agent = input.agent?;
    let family = reference_family(agent.family)?;
    let quic = over_quic(input.hello);
    let ours = Lists::of_hello(input.hello);
    let (client, lists) = choose(candidates, family, quic, agent.major, &ours)?;

    let tls = tls_diff(&ours, &lists);
    // Over QUIC there is no HTTP/2 to compare, and the server reports none.
    let http2 = input.akamai.filter(|_| !quic).map(|yours| Http2Diff {
        yours: yours.to_owned(),
        reference: client.akamai().map(str::to_owned),
        differences: client
            .akamai()
            .map(|reference| http2_differences(yours, reference))
            .unwrap_or_default(),
    });
    let headers = missing_headers(input)
        .filter(|missing| !missing.is_empty())
        .map(|missing| HeadersDiff {
            missing: missing.into_iter().map(|(name, _)| name).collect(),
        });

    let h2_differs = http2.as_ref().is_some_and(|h2| !h2.differences.is_empty());
    if tls.is_empty() && !h2_differs && headers.is_none() {
        return None;
    }
    let source = client.source();
    let kind = SourceKind::of(source);
    Some(Diff {
        reference: Reference {
            family: client.family().to_owned(),
            version: client.version().to_owned(),
            kind,
            also_captured: kind != SourceKind::Captured && source.contains("captured locally"),
            source: source.to_owned(),
        },
        tls,
        http2,
        headers,
    })
}

#[cfg(test)]
mod tests {
    use fingerprint::Extension;

    use super::*;

    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
        (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";

    fn chrome_ua(major: u32) -> String {
        CHROME_UA.replace("Chrome/150", &format!("Chrome/{major}"))
    }

    /// The dataset entry of `family` whose version text starts with `version`.
    fn entry(family: &str, version: &str) -> &'static Client {
        known::clients()
            .iter()
            .find(|client| client.family() == family && client.version().starts_with(version))
            .unwrap_or_else(|| panic!("no {family} {version} entry"))
    }

    fn extension(kind: u16) -> Extension {
        Extension {
            kind,
            data: Vec::new(),
        }
    }

    /// A hello with the cipher suites and extensions of `client`, plus SNI and ALPN.
    fn hello_like(client: &Client) -> ClientHello {
        let lists = Lists::of_ja4_r(client.ja4_r()).expect("dataset JA4_r parses");
        let mut hello = ClientHello::default();
        hello.cipher_suites = lists.ciphers.into_iter().collect();
        hello.extensions = [SERVER_NAME, ALPN]
            .into_iter()
            .chain(lists.extensions)
            .map(extension)
            .collect();
        hello
    }

    fn without_extension(mut hello: ClientHello, kind: u16) -> ClientHello {
        hello.extensions.retain(|extension| extension.kind != kind);
        hello
    }

    #[test]
    fn the_reference_hello_itself_has_no_diff() {
        let chrome = entry("Chrome", "150");
        let hello = hello_like(chrome);
        let mut input = Input::new(&hello, CHROME_UA);
        input.akamai = chrome.akamai();
        assert_eq!(diff(&input), None);
    }

    #[test]
    fn a_missing_extension_is_named_with_its_number() {
        let chrome = entry("Chrome", "150");
        let hello = without_extension(hello_like(chrome), APPLICATION_SETTINGS);
        let found = diff(&Input::new(&hello, CHROME_UA)).expect("a diff");
        assert_eq!(found.reference.family, "Chrome");
        assert!(found.reference.version.starts_with("150-158"));
        assert_eq!(found.reference.kind, SourceKind::CurlImpersonate);
        assert!(found.reference.also_captured);
        assert_eq!(
            found.tls.missing_extensions,
            [Code {
                id: APPLICATION_SETTINGS,
                name: Some("application_settings")
            }]
        );
        assert_eq!(found.tls.extra_extensions, []);
        assert!(found.http2.is_none(), "no HTTP/2 on this connection");
    }

    #[test]
    fn extra_extensions_and_ciphers_are_listed() {
        let mut hello = hello_like(entry("Chrome", "150"));
        hello.extensions.push(extension(0x0016));
        hello.cipher_suites.push(0x0005);
        let found = diff(&Input::new(&hello, CHROME_UA)).expect("a diff");
        assert_eq!(
            found.tls.extra_extensions,
            [Code {
                id: 0x0016,
                name: Some("encrypt_then_mac")
            }]
        );
        assert_eq!(
            found.tls.extra_ciphers,
            [Code {
                id: 0x0005,
                name: Some("TLS_RSA_WITH_RC4_128_SHA")
            }]
        );
        assert_eq!(found.tls.missing_ciphers, []);
    }

    #[test]
    fn grease_sni_and_alpn_are_ignored() {
        let mut hello = hello_like(entry("Chrome", "150"));
        hello.cipher_suites.insert(0, 0x2a2a);
        hello.extensions.insert(0, extension(0x8a8a));
        hello
            .extensions
            .retain(|extension| extension.kind != SERVER_NAME);
        assert_eq!(diff(&Input::new(&hello, CHROME_UA)), None);
    }

    #[test]
    fn no_browser_claim_or_no_reference_gives_no_diff() {
        let hello = ClientHello::default();
        assert_eq!(diff(&Input::new(&hello, "curl/8.7.1")), None);
        assert_eq!(diff(&Input::new(&hello, "")), None);
        assert_eq!(
            diff(&Input::new(&hello, "Mozilla/5.0 (compatible; Bot/1.0)")),
            None
        );
        // A QUIC hello claiming Firefox: the dataset has no Firefox QUIC entry.
        let mut quic = hello;
        quic.extensions = vec![extension(57)];
        let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0";
        assert_eq!(diff(&Input::new(&quic, firefox)), None);
    }

    #[test]
    fn the_range_holding_the_claimed_version_wins_then_the_nearest() {
        let hello = ClientHello::default();
        let reference = |major: u32| {
            diff(&Input::new(&hello, &chrome_ua(major)))
                .expect("an empty hello differs from every reference")
                .reference
                .version
        };
        assert!(reference(85).starts_with("83-87"), "{}", reference(85));
        assert!(reference(90).starts_with("83-87"), "{}", reference(90));
        assert!(reference(140).starts_with("133"), "{}", reference(140));
        assert!(reference(146).starts_with("150-158"), "{}", reference(146));
        // 160 is in two ranges, one of them QUIC only: the TCP one is used.
        assert!(reference(160).starts_with("155-160"), "{}", reference(160));
    }

    #[test]
    fn version_ties_go_to_the_closest_lists() {
        // Chrome 156 lies in 150-158 and in 155-160; a hello close to 155-160 gets that one.
        let canary = entry("Chrome", "155-160");
        let hello = without_extension(hello_like(canary), APPLICATION_SETTINGS);
        let found = diff(&Input::new(&hello, &chrome_ua(156))).expect("a diff");
        assert!(found.reference.version.starts_with("155-160"));
        assert_eq!(found.reference.kind, SourceKind::Captured);
    }

    #[test]
    fn identical_lists_of_another_version_are_not_a_diff() {
        // A Chrome 150 hello under a Chrome 140 User-Agent is for `ua_version` to judge.
        let hello = hello_like(entry("Chrome", "150"));
        assert_eq!(diff(&Input::new(&hello, &chrome_ua(140))), None);
    }

    #[test]
    fn http2_settings_that_differ_are_named() {
        let chrome = entry("Chrome", "150");
        let hello = hello_like(chrome);
        let mut input = Input::new(&hello, CHROME_UA);
        input.akamai = Some("1:65536;2:0;4:65535;6:262144|15663105|0|m,a,s,p");
        let h2 = diff(&input).expect("a diff").http2.expect("an HTTP/2 diff");
        assert_eq!(h2.reference.as_deref(), chrome.akamai());
        assert_eq!(
            h2.differences,
            [Difference {
                field: "SETTINGS INITIAL_WINDOW_SIZE (4)".to_owned(),
                yours: Some("65535".to_owned()),
                reference: Some("6291456".to_owned()),
            }]
        );
    }

    #[test]
    fn an_entry_without_http2_says_so_instead_of_comparing() {
        let old = entry("Chrome", "133");
        let hello = without_extension(hello_like(old), 0x0023);
        let ua = chrome_ua(133);
        let mut input = Input::new(&hello, &ua);
        input.akamai = Some("1:65536|0|0|m,p,a,s");
        let h2 = diff(&input).expect("a diff").http2.expect("an HTTP/2 part");
        assert_eq!(h2.reference, None);
        assert_eq!(h2.differences, []);
    }

    #[test]
    fn missing_headers_come_from_the_headers_check() {
        let hello = hello_like(entry("Chrome", "150"));
        let lines = ["accept-encoding: gzip".to_owned()];
        let mut input = Input::new(&hello, CHROME_UA);
        input.headers = Some(&lines);
        let found = diff(&input).expect("a diff");
        assert!(found.tls.is_empty());
        assert_eq!(
            found.headers.expect("headers").missing,
            ["sec-ch-ua", "sec-fetch-*", "accept-language"]
        );
    }
}
