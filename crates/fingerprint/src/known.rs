//! Known clients: which client a JA4 was seen from, and what a `User-Agent` claims to be.
//!
//! The dataset is `corpus/clients.jsonl`, built into the crate. A match means "identical to a
//! client in the dataset", not proof of identity: a client can copy another's ClientHello, and
//! JA4 sorts ciphers and extensions, so their order plays no part.

use std::sync::LazyLock;

use serde_json::Value;

use crate::Ja4;

const DATASET: &str = include_str!("../../../corpus/clients.jsonl");

static CLIENTS: LazyLock<Vec<Client>> = LazyLock::new(|| {
    parse(DATASET).unwrap_or_else(|error| panic!("corpus/clients.jsonl is invalid: {error}"))
});

/// One line of the dataset: a client and the JA4 it was seen with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    family: String,
    version: String,
    version_min: Option<u32>,
    version_max: Option<u32>,
    library: Option<String>,
    source: String,
    ja4: String,
    ja4_r: String,
    akamai: Option<String>,
}

impl Client {
    /// The client's stable label, such as `Chrome`, `curl` or `Go net/http`.
    #[must_use]
    pub fn family(&self) -> &str {
        &self.family
    }

    /// The version or version range the fingerprint was observed with, as free text.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The lowest and highest major version observed with this fingerprint, when known.
    ///
    /// For browsers these compare with [`UserAgent::major`]. The range covers the observed
    /// samples only; versions between them were not checked.
    #[must_use]
    pub fn version_range(&self) -> Option<(u32, u32)> {
        self.version_min.zip(self.version_max)
    }

    /// The newest version of this entry's family that the dataset has with another
    /// fingerprint: the highest last version, among the entries of the same family, that is
    /// below this entry's first. `None` when the entry has no versions or is the oldest of its
    /// family.
    ///
    /// The versions after it and before this entry's first were not observed, so the dataset
    /// does not say which fingerprint they send. An entry's first version is the oldest one
    /// that was looked at, a uTLS profile's name for most browsers, not the first that sent
    /// the fingerprint.
    #[must_use]
    pub fn previous_version(&self) -> Option<u32> {
        let (first, _) = self.version_range()?;
        clients()
            .iter()
            .filter(|other| other.family == self.family)
            .filter_map(Self::version_range)
            .map(|(_, last)| last)
            .filter(|&last| last < first)
            .max()
    }

    /// The TLS library, when known.
    #[must_use]
    pub fn library(&self) -> Option<&str> {
        self.library.as_deref()
    }

    /// Where the sample came from.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The client's JA4.
    #[must_use]
    pub fn ja4(&self) -> &str {
        &self.ja4
    }

    /// The client's `JA4_r`.
    #[must_use]
    pub fn ja4_r(&self) -> &str {
        &self.ja4_r
    }

    /// The Akamai HTTP/2 fingerprint captured with the same connection; `None` when the
    /// sample did not use HTTP/2 or has no HTTP/2 capture.
    #[must_use]
    pub fn akamai(&self) -> Option<&str> {
        self.akamai.as_deref()
    }

    /// Whether a client of this family is expected to send a `User-Agent` of `agent`'s family.
    ///
    /// Compares families only, not versions. Chromium-based browsers share Chrome's TLS stack,
    /// so a Chrome entry agrees with an Edge `User-Agent` (Brave and Opera send `Chrome/` and
    /// parse as Chrome). A library such as rustls agrees with no family.
    #[must_use]
    pub fn agrees_with(&self, agent: AgentFamily) -> bool {
        match self.family.as_str() {
            "Chrome" => matches!(agent, AgentFamily::Chrome | AgentFamily::Edge),
            "360 Browser" => agent == AgentFamily::Chrome,
            "Firefox" => agent == AgentFamily::Firefox,
            "Safari" => agent == AgentFamily::Safari,
            "curl" => agent == AgentFamily::Curl,
            "Go net/http" => agent == AgentFamily::Go,
            "Python" => agent == AgentFamily::Python,
            "Node.js" => agent == AgentFamily::Node,
            "okhttp" => agent == AgentFamily::OkHttp,
            _ => false,
        }
    }

    /// Parts b and c of the JA4: the cipher hash and the extension hash.
    fn hashes(&self) -> (&str, &str) {
        split(&self.ja4).map_or(("", ""), |(_, b, c)| (b, c))
    }
}

/// How a JA4 relates to the dataset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Match {
    /// The whole JA4 equals this client's.
    Exact(&'static Client),
    /// Only the cipher list (part b) equals this client's. When several clients share the
    /// cipher list, this is the first whose extensions (part c) are equal too, otherwise the
    /// first in the dataset.
    Ciphers(&'static Client),
    /// Nothing in the dataset has this cipher list.
    #[default]
    Unknown,
}

impl Match {
    /// The matched client, exact or by cipher list.
    #[must_use]
    pub fn client(self) -> Option<&'static Client> {
        match self {
            Self::Exact(client) | Self::Ciphers(client) => Some(client),
            Self::Unknown => None,
        }
    }
}

/// Every client of the dataset, in file order.
///
/// # Panics
///
/// Panics if the built-in dataset is invalid, which the crate's tests rule out.
#[must_use]
pub fn clients() -> &'static [Client] {
    &CLIENTS
}

/// Finds the known client that `ja4` matches.
///
/// # Panics
///
/// Panics if the built-in dataset is invalid, which the crate's tests rule out.
#[must_use]
pub fn lookup(ja4: &Ja4) -> Match {
    lookup_in(clients(), ja4.hashed())
}

fn lookup_in(clients: &'static [Client], ja4: &str) -> Match {
    if let Some(client) = clients.iter().find(|client| client.ja4 == ja4) {
        return Match::Exact(client);
    }
    let Some((_, b, c)) = split(ja4) else {
        return Match::Unknown;
    };
    let same_ciphers = || clients.iter().filter(move |client| client.hashes().0 == b);
    same_ciphers()
        .find(|client| client.hashes().1 == c)
        .or_else(|| same_ciphers().next())
        .map_or(Match::Unknown, Match::Ciphers)
}

/// Parts a, b and c of a hashed JA4.
fn split(ja4: &str) -> Option<(&str, &str, &str)> {
    let mut parts = ja4.split('_');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(b), Some(c), None) => Some((a, b, c)),
        _ => None,
    }
}

fn parse(text: &str) -> Result<Vec<Client>, String> {
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            parse_line(line).map_err(|error| format!("line {}: {error}", index + 1))
        })
        .collect()
}

fn parse_line(line: &str) -> Result<Client, String> {
    let value: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
    let text = |key: &str| -> Result<String, String> {
        value[key]
            .as_str()
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| format!("`{key}` must be a non-empty string"))
    };
    let optional_text = |key: &str| -> Result<Option<String>, String> {
        match &value[key] {
            Value::Null => Ok(None),
            _ => text(key).map(Some),
        }
    };
    let optional_major = |key: &str| -> Result<Option<u32>, String> {
        match &value[key] {
            Value::Null => Ok(None),
            number => number
                .as_u64()
                .and_then(|major| u32::try_from(major).ok())
                .map(Some)
                .ok_or_else(|| format!("`{key}` must be a whole number or null")),
        }
    };

    let client = Client {
        family: text("family")?,
        version: text("version")?,
        version_min: optional_major("version_min")?,
        version_max: optional_major("version_max")?,
        library: optional_text("library")?,
        source: text("source")?,
        ja4: text("ja4")?,
        ja4_r: text("ja4_r")?,
        akamai: optional_text("akamai")?,
    };
    if split(&client.ja4).is_none() {
        return Err(format!("`ja4` is not three parts: {}", client.ja4));
    }
    if client.version_min.is_some() != client.version_max.is_some() {
        return Err("`version_min` and `version_max` must be given together".to_owned());
    }
    Ok(client)
}

/// The client families a `User-Agent` can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AgentFamily {
    /// Chrome and the Chromium-based browsers that send `Chrome/` without their own token
    /// that this parser knows, such as Brave and Opera.
    Chrome,
    /// Chromium-based Edge (`Edg/`, `EdgA/`).
    Edge,
    /// Firefox.
    Firefox,
    /// Safari, and the iOS browsers that send `Safari/` without `Chrome/`.
    Safari,
    /// curl.
    Curl,
    /// Go's `net/http` (`Go-http-client/`).
    Go,
    /// Python: `Python-urllib/`, `python-requests/`, `python-httpx/`.
    Python,
    /// Node.js: `node`, `undici`, `node-fetch/`.
    Node,
    /// `OkHttp`.
    OkHttp,
}

impl AgentFamily {
    /// The family's name as the server reports it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Edge => "Edge",
            Self::Firefox => "Firefox",
            Self::Safari => "Safari",
            Self::Curl => "curl",
            Self::Go => "Go",
            Self::Python => "Python",
            Self::Node => "Node",
            Self::OkHttp => "okhttp",
        }
    }
}

/// What a `User-Agent` header claims: a client family and, when stated, its major version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserAgent {
    /// The claimed family.
    pub family: AgentFamily,
    /// The claimed major version of the client itself.
    ///
    /// `None` when the header carries no such number: `Go-http-client/2.0` states the HTTP
    /// version, `python-requests/` and `python-httpx/` state the library's version, and `node`
    /// states none.
    pub major: Option<u32>,
    /// The number after the first dot of that version: 4 for Safari's `Version/16.4`.
    ///
    /// `None` without a major version, and when no number follows it.
    pub minor: Option<u32>,
}

impl UserAgent {
    /// Reads the family and major version out of a `User-Agent` value.
    ///
    /// Recognizes Chrome, Edge, Firefox, Safari, curl, Go's `net/http`, Python (urllib,
    /// requests, httpx), Node.js and `OkHttp`; anything else is `None`. This is a minimal
    /// reading of what the header claims, not a general `User-Agent` parser.
    #[must_use]
    pub fn parse(user_agent: &str) -> Option<Self> {
        let user_agent = user_agent.trim();
        let lower = user_agent.to_ascii_lowercase();
        // The family with the version that starts `version`, or with none.
        let known = |family, version: Option<&str>| {
            let (major, minor) = version.map_or((None, None), major_minor);
            Some(Self {
                family,
                major,
                minor,
            })
        };

        // Tools name themselves in the first product token.
        if let Some(version) = lower.strip_prefix("curl/") {
            return known(AgentFamily::Curl, Some(version));
        }
        if lower.starts_with("go-http-client/") {
            return known(AgentFamily::Go, None);
        }
        if let Some(version) = lower.strip_prefix("python-urllib/") {
            return known(AgentFamily::Python, Some(version));
        }
        if lower.starts_with("python-requests/") || lower.starts_with("python-httpx/") {
            return known(AgentFamily::Python, None);
        }
        if let Some(version) = lower.strip_prefix("okhttp/") {
            return known(AgentFamily::OkHttp, Some(version));
        }
        if lower == "node" || lower.starts_with("undici") || lower.starts_with("node-fetch/") {
            return known(AgentFamily::Node, None);
        }

        // Browsers: the most specific token wins, since Edge also says Chrome and Safari, and
        // Chrome also says Safari.
        let after = |token: &str| {
            user_agent
                .find(token)
                .map(|at| &user_agent[at + token.len()..])
        };
        if let Some(version) = after("Edg/").or_else(|| after("EdgA/")) {
            return known(AgentFamily::Edge, Some(version));
        }
        if let Some(version) = after("Firefox/") {
            return known(AgentFamily::Firefox, Some(version));
        }
        if let Some(version) = after("Chrome/").or_else(|| after("Chromium/")) {
            return known(AgentFamily::Chrome, Some(version));
        }
        if after("Safari/").is_some() {
            return known(AgentFamily::Safari, after("Version/"));
        }
        None
    }
}

/// The number a version starts with, and the number after the dot that follows it.
fn major_minor(version: &str) -> (Option<u32>, Option<u32>) {
    let number = |text: &str| -> Option<u32> {
        let digits = text
            .find(|c: char| !c.is_ascii_digit())
            .map_or(text, |end| &text[..end]);
        digits.parse().ok()
    };
    let Some(major) = number(version) else {
        return (None, None);
    };
    let rest = version.trim_start_matches(|c: char| c.is_ascii_digit());
    (Some(major), rest.strip_prefix('.').and_then(number))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::ja4::hash;

    /// Families [`Client::agrees_with`] knows; `rustls` is a library and agrees with none.
    const FAMILIES: [&str; 10] = [
        "Chrome",
        "360 Browser",
        "Firefox",
        "Safari",
        "curl",
        "Go net/http",
        "Python",
        "Node.js",
        "okhttp",
        "rustls",
    ];

    const CHROME_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
        (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36";

    fn client(family: &str) -> &'static Client {
        clients()
            .iter()
            .find(|client| client.family == family)
            .unwrap_or_else(|| panic!("no {family} entry in the dataset"))
    }

    #[test]
    fn every_dataset_line_parses() {
        for (index, line) in DATASET.lines().enumerate() {
            if let Err(error) = parse_line(line) {
                panic!("line {}: {error}", index + 1);
            }
        }
        assert_eq!(clients().len(), DATASET.lines().count());
        assert!(
            clients().len() >= 20,
            "dataset too small: {}",
            clients().len()
        );
    }

    #[test]
    fn ja4s_are_unique() {
        let mut seen = HashSet::new();
        for client in clients() {
            assert!(seen.insert(client.ja4()), "duplicate JA4 {}", client.ja4());
        }
    }

    #[test]
    fn each_ja4_is_the_hash_of_its_ja4_r() {
        for client in clients() {
            let mut parts = client.ja4_r().splitn(3, '_');
            let (a, b, c) = (parts.next(), parts.next(), parts.next());
            let (Some(a), Some(b), Some(c)) = (a, b, c) else {
                panic!("JA4_r is not three parts: {}", client.ja4_r());
            };
            assert_eq!(
                client.ja4(),
                format!("{a}_{}_{}", hash(b), hash(c)),
                "{} {}",
                client.family(),
                client.version()
            );
        }
    }

    #[test]
    fn families_and_version_ranges_are_well_formed() {
        for client in clients() {
            assert!(
                FAMILIES.contains(&client.family()),
                "family {:?} is unknown to agrees_with",
                client.family()
            );
            if let Some((min, max)) = client.version_range() {
                assert!(min <= max, "{} {}", client.family(), client.version());
            }
        }
    }

    #[test]
    fn rejects_malformed_lines() {
        let line = |ja4: &str, extra: &str| {
            format!(
                r#"{{"family":"X","version":"1","source":"test","ja4":"{ja4}","ja4_r":"a_b_c"{extra}}}"#
            )
        };
        assert!(parse_line(&line("t13d0101h2_aaaaaaaaaaaa_bbbbbbbbbbbb", "")).is_ok());
        assert!(parse_line(&line("t13d0101h2_aaaaaaaaaaaa", "")).is_err());
        assert!(parse_line(&line("a_b_c", r#","version_min":1"#)).is_err());
        assert!(parse_line(&line("a_b_c", r#","version_min":"1","version_max":2"#)).is_err());
        assert!(parse_line(&line("a_b_c", r#","library":"""#)).is_err());
        assert!(parse_line(r#"{"family":"X"}"#).is_err());
        assert!(parse_line("not json").is_err());
    }

    #[test]
    fn exact_match_returns_the_entry() {
        for client in clients() {
            assert_eq!(lookup_in(clients(), client.ja4()), Match::Exact(client));
        }
    }

    #[test]
    fn a_different_part_a_is_a_cipher_match_with_the_same_entry() {
        // curl's HTTP/2 and HTTP/1.1 hellos differ only in ALPN, so only in part a.
        let curl = client("curl");
        let (a, b, c) = split(curl.ja4()).expect("three parts");
        assert_eq!(a, "t13d4907h2");
        let no_alpn = format!("t13d490700_{b}_{c}");
        assert_eq!(lookup_in(clients(), &no_alpn), Match::Ciphers(curl));
    }

    #[test]
    fn same_ciphers_prefer_the_entry_with_the_same_extensions() {
        // Two entries with one cipher list and different extensions: Chrome versions.
        let (first, later) = clients()
            .iter()
            .enumerate()
            .find_map(|(index, later)| {
                let first = clients()[..index]
                    .iter()
                    .find(|client| client.hashes().0 == later.hashes().0)?;
                (first.hashes().1 != later.hashes().1).then_some((first, later))
            })
            .expect("two entries share a cipher list and differ in extensions");
        let (b, c) = later.hashes();

        let same_extensions = format!("q13d0000h3_{b}_{c}");
        assert_eq!(
            lookup_in(clients(), &same_extensions),
            Match::Ciphers(later)
        );
        let unseen_extensions = format!("q13d0000h3_{b}_ffffffffffff");
        assert_eq!(
            lookup_in(clients(), &unseen_extensions),
            Match::Ciphers(first)
        );
    }

    #[test]
    fn unseen_ciphers_and_malformed_ja4_are_unknown() {
        let chrome = client("Chrome");
        let (a, _, c) = split(chrome.ja4()).expect("three parts");
        let unseen_ciphers = format!("{a}_ffffffffffff_{c}");
        assert_eq!(lookup_in(clients(), &unseen_ciphers), Match::Unknown);
        assert_eq!(lookup_in(clients(), ""), Match::Unknown);
        assert_eq!(lookup_in(clients(), "t13d1516h2"), Match::Unknown);
        assert_eq!(Match::Unknown.client(), None);
    }

    #[test]
    fn user_agent_families_and_majors() {
        type Claim = Option<(AgentFamily, Option<u32>)>;
        let cases: [(&str, Claim); 20] = [
            (CHROME_UA, Some((AgentFamily::Chrome, Some(133)))),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like \
                 Gecko) HeadlessChrome/160.0.0.0 Safari/537.36",
                Some((AgentFamily::Chrome, Some(160))),
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86",
                Some((AgentFamily::Edge, Some(131))),
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0",
                Some((AgentFamily::Chrome, Some(130))),
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                Some((AgentFamily::Firefox, Some(120))),
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, \
                 like Gecko) Version/16.0 Safari/605.1.15",
                Some((AgentFamily::Safari, Some(16))),
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 \
                 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1",
                Some((AgentFamily::Safari, None)),
            ),
            ("curl/8.7.1", Some((AgentFamily::Curl, Some(8)))),
            ("Go-http-client/2.0", Some((AgentFamily::Go, None))),
            ("Go-http-client/1.1", Some((AgentFamily::Go, None))),
            ("Python-urllib/3.9", Some((AgentFamily::Python, Some(3)))),
            ("python-requests/2.32.3", Some((AgentFamily::Python, None))),
            ("python-httpx/0.28.1", Some((AgentFamily::Python, None))),
            ("node", Some((AgentFamily::Node, None))),
            ("undici", Some((AgentFamily::Node, None))),
            ("okhttp/4.12.0", Some((AgentFamily::OkHttp, Some(4)))),
            ("  curl/7.88.1  ", Some((AgentFamily::Curl, Some(7)))),
            ("", None),
            ("Wget/1.21.4", None),
            ("rustls-get", None),
        ];
        for (text, expected) in cases {
            let parsed = UserAgent::parse(text).map(|agent| (agent.family, agent.major));
            assert_eq!(parsed, expected, "User-Agent {text:?}");
        }
    }

    #[test]
    fn the_previous_version_is_the_newest_older_one_of_the_family() {
        let by_version = |family: &str, version: &str| {
            clients()
                .iter()
                .find(|c| c.family() == family && c.version() == version)
                .unwrap_or_else(|| panic!("no entry {family} {version}"))
        };
        // Chrome 96-114 and 100-115 come before the two entries that start at 120.
        let padded = by_version("Chrome", "120 (hello with the padding extension)");
        assert_eq!(padded.previous_version(), Some(115));
        assert_eq!(
            by_version("Chrome", "120-131").previous_version(),
            Some(115)
        );
        assert_eq!(by_version("Chrome", "133").previous_version(), Some(131));
        assert_eq!(by_version("Chrome", "58-62").previous_version(), None);
        assert_eq!(by_version("Firefox", "120").previous_version(), Some(105));
        // One curl version was captured, so nothing is known about older ones.
        assert_eq!(by_version("curl", "8.7.1").previous_version(), None);
    }

    #[test]
    fn user_agent_minor_versions() {
        let minor = |text: &str| UserAgent::parse(text).expect("known").minor;
        let safari = |version: &str| {
            format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, \
                 like Gecko) Version/{version} Safari/605.1.15"
            )
        };
        assert_eq!(minor(&safari("16.4")), Some(4));
        assert_eq!(minor(&safari("16.3.1")), Some(3));
        assert_eq!(minor(&safari("17.0")), Some(0));
        assert_eq!(minor(&safari("16")), None);
        assert_eq!(minor(&safari("16.")), None);
        assert_eq!(minor(&safari("x")), None, "no major version, no minor");
        assert_eq!(minor("curl/8.7.1"), Some(7));
        assert_eq!(minor(CHROME_UA), Some(0));
        assert_eq!(minor("Go-http-client/2.0"), None);
    }

    #[test]
    fn chromium_browsers_agree_with_a_chrome_entry() {
        let chrome = client("Chrome");
        assert!(chrome.agrees_with(AgentFamily::Chrome));
        assert!(chrome.agrees_with(AgentFamily::Edge));
        assert!(!chrome.agrees_with(AgentFamily::Firefox));
        assert!(!chrome.agrees_with(AgentFamily::Go));
        assert!(client("Go net/http").agrees_with(AgentFamily::Go));
        assert!(!client("Go net/http").agrees_with(AgentFamily::Chrome));
        assert!(client("curl").agrees_with(AgentFamily::Curl));
        assert!(!client("rustls").agrees_with(AgentFamily::Chrome));
    }

    #[test]
    fn local_http2_captures_carry_an_akamai_fingerprint() {
        assert_eq!(
            client("curl").akamai(),
            Some("3:100;4:10485760;2:0|1048510465|0|m,s,a,p")
        );
        let from_profiles = clients()
            .iter()
            .filter(|client| client.source().starts_with("uTLS"));
        for client in from_profiles {
            assert_eq!(client.akamai(), None, "{}", client.source());
        }
    }
}
