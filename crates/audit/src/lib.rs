//! Consistency audit of one connection.
//!
//! Systems that detect bots, proxies and imitated browsers rarely trust a single fingerprint.
//! They compare layers: what the User-Agent claims, what the TLS ClientHello looks like, how
//! HTTP/2 was opened, which headers came along, and what the TCP stack looks like. A real
//! client agrees with itself on every layer; an imitation or a proxied connection usually
//! does not. [`audit`] runs those comparisons and reports each one, with a score.
//!
//! The score says how consistent the client looks to this tool. It is not a guarantee: a
//! check can only use the layers the server could observe and the clients it knows.

mod checks;
mod diff;

pub use diff::{Code, Diff, Difference, HeadersDiff, Http2Diff, Reference, SourceKind, TlsDiff};

use fingerprint::ClientHello;
use fingerprint::known::{Match, UserAgent};
use serde::Serialize;

/// Outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The layers agree.
    Pass,
    /// Unusual, but real clients do it too.
    Warn,
    /// A real client of the claimed kind does not do this.
    Fail,
    /// Not measured: the server lacked the data.
    Skip,
}

/// One comparison and what it found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    /// Stable identifier, such as `ua_tls`.
    pub id: &'static str,
    /// Outcome.
    pub status: Status,
    /// What was compared, in a few words.
    pub title: &'static str,
    /// What was found, with the values involved.
    pub detail: String,
    /// Points this outcome takes off the score.
    #[serde(skip)]
    pub penalty: u8,
}

/// Summary of the score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Nothing gives the client away.
    Consistent,
    /// Something is off; a strict filter would look closer.
    Suspicious,
    /// The layers contradict each other.
    Inconsistent,
}

/// The audit of one connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Audit {
    /// 100 minus the penalties of the checks, not below 0.
    pub score: u8,
    /// The score in a word.
    pub verdict: Verdict,
    /// Every check that applied, in a fixed order.
    pub checks: Vec<Check>,
    /// What separates the connection from the recorded reference of the browser its
    /// User-Agent claims; `None` when it claims none the dataset has, or nothing differs.
    /// Information only: it takes nothing off the score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<Diff>,
}

/// The TCP SYN of the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Syn<'a> {
    /// IP time to live (hop limit) as received.
    pub ttl: u8,
    /// Maximum segment size option; 0 when absent.
    pub mss: u16,
    /// Whether the packet was IPv6.
    pub ipv6: bool,
    /// TCP option names in order, joined with commas, such as `mss,sackOK,timestamp,nop,wscale`.
    pub option_order: &'a str,
}

/// Everything the server observed about one connection.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Input<'a> {
    /// The ClientHello, read with [`ClientHello::parse`].
    pub hello: &'a ClientHello,
    /// The User-Agent header; empty when absent.
    pub user_agent: &'a str,
    /// What the User-Agent claims, when it names a client we know.
    pub agent: Option<UserAgent>,
    /// The known client the TLS fingerprint matches.
    pub known: Match,
    /// The HTTP/2 fingerprint of this connection, when it used HTTP/2.
    pub akamai: Option<&'a str>,
    /// Request header lines (`name: value`) in the order received, when the server saw them.
    pub headers: Option<&'a [String]>,
    /// The TCP SYN, when the server captured it.
    pub syn: Option<Syn<'a>>,
}

impl<'a> Input<'a> {
    /// An input with the ClientHello and the User-Agent, which is parsed for its claim; set
    /// the other fields as known.
    #[must_use]
    pub fn new(hello: &'a ClientHello, user_agent: &'a str) -> Self {
        Self {
            hello,
            user_agent,
            agent: UserAgent::parse(user_agent),
            known: Match::Unknown,
            akamai: None,
            headers: None,
            syn: None,
        }
    }
}

/// Scores at or above this are [`Verdict::Consistent`].
const CONSISTENT_FROM: u8 = 90;
/// Scores at or above this, and below [`CONSISTENT_FROM`], are [`Verdict::Suspicious`].
const SUSPICIOUS_FROM: u8 = 60;

/// Runs every check that applies to `input`.
#[must_use]
pub fn audit(input: &Input<'_>) -> Audit {
    let checks: Vec<Check> = [
        Some(checks::tls_known(input)),
        checks::ua_tls(input),
        checks::tls_traits(input),
        checks::ua_version(input),
        checks::alps_alpn(input),
        checks::grease(input),
        checks::http2(input),
        checks::headers(input),
        checks::tcp_os(input),
        checks::tcp_mss(input),
    ]
    .into_iter()
    .flatten()
    .collect();

    let penalty: u32 = checks.iter().map(|check| u32::from(check.penalty)).sum();
    let score = u8::try_from(100_u32.saturating_sub(penalty)).unwrap_or(0);
    let verdict = if score >= CONSISTENT_FROM {
        Verdict::Consistent
    } else if score >= SUSPICIOUS_FROM {
        Verdict::Suspicious
    } else {
        Verdict::Inconsistent
    };
    Audit {
        score,
        verdict,
        checks,
        diff: diff::diff(input),
    }
}
