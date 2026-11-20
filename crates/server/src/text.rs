//! The plain-text report for terminals: what `curl https://host/` prints.
//!
//! The text is ASCII, [`WIDTH`] columns wide at most, and plain unless [`Colour::Ansi`] is asked
//! for. Everything the client chose (User-Agent family, SNI, ALPN, address) is escaped, so a
//! client cannot send terminal escape sequences back to its own screen or to a pipe.

use std::mem;

use audit::{Audit, Check, Status, Verdict};
use serde_json::Value;

use crate::printable::MAX_PRINTED;
use crate::report::{Report, TlsDetails};

/// Columns a line may take.
const WIDTH: usize = 78;
/// Cells of the score bar; a full score fills all of them.
const BAR_CELLS: usize = 20;
/// Width of the name column of the fingerprint table.
const FINGERPRINT_LABEL: usize = 9;
/// Width of the label column of the TLS block: the longest label, "Highest TLS version offered".
const TLS_LABEL: usize = 27;
/// Indent of every entry under a section title.
const INDENT: &str = "  ";
/// Columns between a label and its value.
const LABEL_GAP: usize = 2;
/// The hint line at the end of the report; it is [`WIDTH`] columns or fewer.
const FOOTER: &str =
    "colour: ?color=1  JSON: /api/all  short JSON: /api/clean  page: /?format=html";

/// ANSI SGR sequences, the only escape codes the renderer writes.
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";

/// Whether the text carries ANSI colour codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Colour {
    /// No escape codes, so a pipe or a file stays clean.
    Plain,
    /// Bold, green, yellow, red and dim, for a terminal.
    Ansi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    Bold,
    Dim,
    Red,
    Green,
    Yellow,
}

impl Style {
    const fn code(self) -> &'static str {
        match self {
            Self::Bold => BOLD,
            Self::Dim => DIM,
            Self::Red => RED,
            Self::Green => GREEN,
            Self::Yellow => YELLOW,
        }
    }
}

impl Colour {
    /// `text` wrapped in the codes of `styles`; layout is always computed on the bare text.
    fn paint(self, styles: &[Style], text: &str) -> String {
        if self == Self::Plain || styles.is_empty() || text.is_empty() {
            return text.to_owned();
        }
        let codes: String = styles.iter().map(|style| style.code()).collect();
        format!("{codes}{text}{RESET}")
    }
}

/// Renders `report` as text.
pub(crate) fn render(report: &Report, colour: Colour) -> String {
    render_with(
        report,
        report.audit().as_ref(),
        &report.client_json(),
        colour,
    )
}

/// [`render`] with the audit and the `client` object given, so a test can fix both.
fn render_with(report: &Report, audit: Option<&Audit>, client: &Value, colour: Colour) -> String {
    let mut page = Page {
        out: String::new(),
        colour,
    };
    page.title(report);
    if let (Some(tls), Some(audit)) = (&report.tls, audit) {
        page.verdict(audit, client);
        page.checks(audit);
        page.fingerprints(report, tls);
        page.tls(tls);
    } else {
        page.blank();
        page.entry(
            "",
            0,
            "No TLS ClientHello was captured for this connection, so there is nothing to \
             audit or fingerprint.",
            &[],
        );
    }
    page.blank();
    // Not wrapped: the two spaces between the hints are part of the layout.
    page.push_line(&colour.paint(&[Style::Dim], FOOTER));
    page.out
}

struct Page {
    out: String,
    colour: Colour,
}

impl Page {
    fn push_line(&mut self, line: &str) {
        self.out.push_str(line);
        self.out.push('\n');
    }

    fn blank(&mut self) {
        self.out.push('\n');
    }

    /// `head` (already painted, `head_width` columns wide) and `text` wrapped to the rest of the
    /// line; later lines are indented to `head_width`, so the text hangs under its own start.
    fn entry(&mut self, head: &str, head_width: usize, text: &str, styles: &[Style]) {
        let hanging = " ".repeat(head_width);
        for (i, line) in wrap(text, WIDTH - head_width).iter().enumerate() {
            let start = if i == 0 { head } else { hanging.as_str() };
            let line = format!("{start}{}", self.colour.paint(styles, line));
            self.push_line(line.trim_end());
        }
    }

    /// `TITLE ------` filled to [`WIDTH`], after a blank line.
    fn section(&mut self, title: &str) {
        self.blank();
        let rule = "-".repeat(WIDTH - title.len() - 1);
        let line = format!(
            "{} {}",
            self.colour.paint(&[Style::Bold], title),
            self.colour.paint(&[Style::Dim], &rule)
        );
        self.push_line(&line);
    }

    /// A table row: a label column of `label_width` columns, then the value, wrapped.
    fn row(&mut self, label: &str, label_width: usize, value: &str, styles: &[Style]) {
        let head = format!("{INDENT}{label:<label_width$}{}", " ".repeat(LABEL_GAP));
        self.entry(&head, head.len(), value, styles);
    }

    fn title(&mut self, report: &Report) {
        let mut facts = vec![clean(&report.http_version)];
        if let Some(tls) = &report.tls {
            facts.extend(version_name(tls.negotiated_version));
        }
        facts.push(client_text(&report.ip));
        let head = format!("{}  ", self.colour.paint(&[Style::Bold], "mirrust"));
        let text = format!("({})", facts.join(", "));
        self.entry(&head, "mirrust  ".len(), &text, &[]);
    }

    /// The score, its bar and verdict, and who the client looks like.
    fn verdict(&mut self, audit: &Audit, client: &Value) {
        let tone = match audit.verdict {
            Verdict::Consistent => Style::Green,
            Verdict::Suspicious => Style::Yellow,
            Verdict::Inconsistent => Style::Red,
        };
        let filled = (usize::from(audit.score) * BAR_CELLS + 50) / 100;
        let bar = format!(
            "[{}{}]",
            "#".repeat(filled.min(BAR_CELLS)),
            " ".repeat(BAR_CELLS - filled.min(BAR_CELLS))
        );
        let verdict = match audit.verdict {
            Verdict::Consistent => "consistent",
            Verdict::Suspicious => "suspicious",
            Verdict::Inconsistent => "inconsistent",
        };
        self.blank();
        let line = format!(
            "{}  {}  {}  {}",
            self.colour.paint(&[Style::Bold], "AUDIT"),
            self.colour
                .paint(&[Style::Bold, tone], &format!("{}/100", audit.score)),
            self.colour.paint(&[tone], &bar),
            self.colour.paint(&[tone], verdict),
        );
        self.push_line(&line);
        self.entry(INDENT, INDENT.len(), &looks_like(audit, client), &[]);
    }

    /// The counts line, then every check, problems first.
    fn checks(&mut self, audit: &Audit) {
        let mut checks: Vec<&Check> = audit.checks.iter().collect();
        // Stable: within a status the order of `audit.checks` is kept.
        checks.sort_by_key(|check| rank(check.status));
        self.blank();
        self.entry(INDENT, INDENT.len(), &counts(&checks), &[Style::Dim]);
        for check in checks {
            let (badge, tone) = match check.status {
                Status::Fail => ("[FAIL]", Style::Red),
                Status::Warn => ("[WARN]", Style::Yellow),
                Status::Pass => ("[ ok ]", Style::Green),
                Status::Skip => ("[skip]", Style::Dim),
            };
            let dim: &[Style] = if check.status == Status::Skip {
                &[Style::Dim]
            } else {
                &[]
            };
            let head = format!("{INDENT}{} ", self.colour.paint(&[tone], badge));
            let head_width = INDENT.len() + badge.len() + 1;
            let title: &[Style] = if check.status == Status::Skip {
                &[Style::Dim]
            } else {
                &[Style::Bold]
            };
            self.entry(&head, head_width, &clean(check.title), title);
            self.entry(
                &" ".repeat(head_width),
                head_width,
                &clean(&check.detail),
                dim,
            );
        }
    }

    fn fingerprints(&mut self, report: &Report, tls: &TlsDetails) {
        self.section("FINGERPRINTS");
        let mut rows = vec![
            ("ja4", tls.ja4.as_str(), None),
            ("ja4_o", tls.ja4_o.as_str(), None),
            ("ja3", tls.ja3_hash.as_str(), None),
            ("peetprint", tls.peetprint_hash.as_str(), None),
        ];
        if let Some(h2) = &report.http2 {
            let akamai = (
                "akamai",
                h2.akamai_fingerprint_hash.as_str(),
                Some(h2.akamai_fingerprint.as_str()),
            );
            rows.push(akamai);
        }
        if let Some(h3) = &report.http3 {
            rows.push((
                "http3",
                h3.fingerprint_hash.as_str(),
                Some(h3.fingerprint.as_str()),
            ));
        }
        for (label, hash, readable) in rows {
            self.row(label, FINGERPRINT_LABEL, &clean(hash), &[]);
            if let Some(readable) = readable {
                let width = INDENT.len() + FINGERPRINT_LABEL + LABEL_GAP;
                self.entry(&" ".repeat(width), width, &clean(readable), &[Style::Dim]);
            }
        }
    }

    fn tls(&mut self, tls: &TlsDetails) {
        self.section("TLS");
        for signal in signals(tls) {
            let styles: Vec<Style> = signal.tone.into_iter().collect();
            self.row(signal.label, TLS_LABEL, &signal.value, &styles);
        }
    }
}

/// Greedy word wrap to `width` columns. A word longer than a line is cut at the line end, the
/// only case where text is split inside a word.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut line_len = 0;
    for word in text.split_whitespace() {
        let mut word_len = word.chars().count();
        if line_len > 0 && line_len + 1 + word_len > width {
            lines.push(mem::take(&mut line));
            line_len = 0;
        }
        let mut word = word;
        while word_len > width {
            let cut = word
                .char_indices()
                .nth(width)
                .map_or(word.len(), |(i, _)| i);
            lines.push(word[..cut].to_owned());
            word = &word[cut..];
            word_len -= width;
        }
        if line_len > 0 {
            line.push(' ');
            line_len += 1;
        }
        line.push_str(word);
        line_len += word_len;
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// `text` with every character that is not printable ASCII written as an escape (`\n`,
/// `\u{1b}`), so the result is ASCII and cannot drive a terminal.
fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii_graphic() || c == ' ' {
            out.push(c);
        } else {
            out.extend(c.escape_default());
        }
    }
    out
}

/// [`clean`] for text the client chose, cut at [`MAX_PRINTED`] characters with `...`.
fn client_text(text: &str) -> String {
    let kept: String = text.chars().take(MAX_PRINTED).collect();
    let mut out = clean(&kept);
    if text.chars().nth(MAX_PRINTED).is_some() {
        out.push_str("...");
    }
    out
}

fn rank(status: Status) -> u8 {
    match status {
        Status::Fail => 0,
        Status::Warn => 1,
        Status::Pass => 2,
        Status::Skip => 3,
    }
}

/// `6 checks passed, 1 not measured`, or with problems `1 failed, 4 passed, ...`.
fn counts(checks: &[&Check]) -> String {
    let count = |status| checks.iter().filter(|check| check.status == status).count();
    let (failed, unusual) = (count(Status::Fail), count(Status::Warn));
    let (passed, skipped) = (count(Status::Pass), count(Status::Skip));
    let mut parts = Vec::new();
    if failed > 0 {
        parts.push(format!("{failed} failed"));
    }
    if unusual > 0 {
        parts.push(format!("{unusual} unusual"));
    }
    if passed > 0 {
        let noun = if failed + unusual > 0 {
            ""
        } else if passed == 1 {
            " check"
        } else {
            " checks"
        };
        parts.push(format!("{passed}{noun} passed"));
    }
    if skipped > 0 {
        parts.push(format!("{skipped} not measured"));
    }
    if parts.is_empty() {
        "no checks ran".to_owned()
    } else {
        parts.join(", ")
    }
}

/// What the TLS stack looks like and what the User-Agent claims, as the page words it.
fn looks_like(audit: &Audit, client: &Value) -> String {
    let name = ["family", "version"]
        .iter()
        .filter_map(|key| client[key].as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let same_lists = audit
        .checks
        .iter()
        .any(|check| check.id == "tls_known" && check.status == Status::Pass);
    let looks = match client["match"].as_str() {
        Some("exact") => format!("{name} (exact match)"),
        Some("ciphers") if same_lists => format!("{name} (same cipher suites)"),
        Some("ciphers") => format!("close to {name}"),
        _ => "no known client".to_owned(),
    };
    let claims = client["user_agent_family"]
        .as_str()
        .filter(|family| *family != "unknown")
        .unwrap_or("nothing we recognise");
    clean(&format!(
        "Looks like {looks}. The User-Agent claims {claims}."
    ))
}

/// One line of the TLS block.
struct Signal {
    label: &'static str,
    value: String,
    tone: Option<Style>,
}

fn is_grease(name: &str) -> bool {
    name.to_ascii_uppercase().contains("GREASE")
}

/// Drops the ` (123)` id appended to registry names.
fn bare(name: &str) -> &str {
    name.rsplit_once(" (")
        .filter(|(_, id)| id.strip_suffix(')').is_some_and(is_number))
        .map_or(name, |(bare, _)| bare)
}

fn is_number(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

fn version_name(version: u16) -> Option<String> {
    match version {
        0 => None,
        769 => Some("TLS 1.0".to_owned()),
        770 => Some("TLS 1.1".to_owned()),
        771 => Some("TLS 1.2".to_owned()),
        772 => Some("TLS 1.3".to_owned()),
        other => Some(format!("TLS 0x{other:04x}")),
    }
}

/// The extension whose name starts with `prefix`, such as `key_share`.
fn extension<'tls>(tls: &'tls TlsDetails, prefix: &str) -> Option<&'tls Value> {
    tls.extensions
        .as_array()?
        .iter()
        .find(|ext| ext["name"].as_str().is_some_and(|n| n.starts_with(prefix)))
}

/// The strings of `value[key]` that are not GREASE.
fn names<'a>(value: Option<&'a Value>, key: &str) -> Vec<&'a str> {
    value
        .and_then(|value| value[key].as_array())
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|name| !is_grease(name))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CipherKind {
    /// RC4, 3DES, MD5 and the like.
    Broken,
    /// No forward secrecy, or CBC mode.
    Weak,
}

/// Key exchanges without forward secrecy: RSA, static (EC)DH and plain PSK. The ephemeral
/// ones are `TLS_DHE_` and `TLS_ECDHE_`.
const NO_FORWARD_SECRECY: [&str; 4] = ["TLS_RSA_", "TLS_DH_", "TLS_ECDH_", "TLS_PSK_"];

fn cipher_kind(name: &str) -> Option<CipherKind> {
    if is_grease(name) || !name.starts_with("TLS_") {
        return None;
    }
    let broken = ["RC4", "3DES", "_DES_", "NULL", "EXPORT", "anon"]
        .iter()
        .any(|part| name.contains(part))
        || name.ends_with("_MD5");
    if broken {
        Some(CipherKind::Broken)
    } else if NO_FORWARD_SECRECY.iter().any(|kx| name.starts_with(kx)) || name.contains("_CBC_") {
        Some(CipherKind::Weak)
    } else {
        None
    }
}

/// What stands out about the client's ClientHello; the "At a glance" panel of the page.
fn signals(tls: &TlsDetails) -> Vec<Signal> {
    let mut out = Vec::new();

    let versions = names(extension(tls, "supported_versions"), "versions");
    let best = versions
        .first()
        .map(|version| (*version).to_owned())
        .or_else(|| version_name(tls.negotiated_version))
        .unwrap_or_else(|| "unknown".to_owned());
    let others: Vec<&str> = versions
        .iter()
        .skip(1)
        .map(|version| version.strip_prefix("TLS ").unwrap_or(version))
        .collect();
    let value = if versions.is_empty() {
        format!("{best} (no supported_versions extension)")
    } else if others.is_empty() {
        best.clone()
    } else {
        format!("{best} (also {})", others.join(", "))
    };
    out.push(Signal {
        label: "Highest TLS version offered",
        tone: Some(if best == "TLS 1.3" {
            Style::Green
        } else {
            Style::Yellow
        }),
        value: clean(&value),
    });

    let real_ciphers: Vec<&str> = tls
        .ciphers
        .iter()
        .map(String::as_str)
        .filter(|name| !is_grease(name))
        .collect();
    out.push(plain("Cipher suites", real_ciphers.len().to_string()));
    let extensions = tls.extensions.as_array().map_or(0, |all| {
        all.iter()
            .filter(|ext| !ext["name"].as_str().is_some_and(is_grease))
            .count()
    });
    out.push(plain("Extensions", extensions.to_string()));

    let alpn = names(
        extension(tls, "application_layer_protocol_negotiation"),
        "protocols",
    );
    let alpn = if alpn.is_empty() {
        "None".to_owned()
    } else {
        alpn.iter()
            .map(|protocol| client_text(protocol))
            .collect::<Vec<_>>()
            .join(", ")
    };
    out.push(plain("ALPN", alpn));
    let sni = extension(tls, "server_name").and_then(|ext| ext["server_name"].as_str());
    out.push(plain(
        "Server name (SNI)",
        sni.map_or_else(|| "None".to_owned(), client_text),
    ));

    out.push(post_quantum(tls));

    let ech = tls.extensions.as_array().is_some_and(|all| {
        all.iter()
            .any(|ext| ext["name"].as_str().is_some_and(|n| n.ends_with("(65037)")))
    });
    out.push(Signal {
        label: "Encrypted ClientHello",
        value: if ech { "Sent" } else { "Not sent" }.to_owned(),
        tone: None,
    });

    let broken = real_ciphers
        .iter()
        .filter(|name| cipher_kind(name) == Some(CipherKind::Broken))
        .count();
    let weak = real_ciphers
        .iter()
        .filter(|name| cipher_kind(name).is_some())
        .count();
    let legacy = match (weak, broken) {
        (0, _) => "None".to_owned(),
        (weak, 0) => format!("{weak} of {}", real_ciphers.len()),
        (weak, broken) => format!("{weak} of {} ({broken} broken)", real_ciphers.len()),
    };
    out.push(Signal {
        label: "Legacy cipher suites",
        value: legacy,
        tone: Some(match (weak, broken) {
            (0, _) => Style::Green,
            (_, 0) => Style::Yellow,
            _ => Style::Red,
        }),
    });

    let grease = tls.ciphers.iter().any(|name| is_grease(name));
    out.push(plain(
        "GREASE",
        if grease { "Yes" } else { "No" }.to_owned(),
    ));

    out
}

fn plain(label: &'static str, value: String) -> Signal {
    Signal {
        label,
        value,
        tone: None,
    }
}

fn post_quantum(tls: &TlsDetails) -> Signal {
    const LABEL: &str = "Post-quantum key exchange";
    let groups = names(extension(tls, "supported_groups"), "supported_groups");
    let is_pq = |name: &str| {
        let name = name.to_ascii_uppercase();
        name.contains("MLKEM") || name.contains("KYBER")
    };
    let Some(group) = groups.iter().find(|group| is_pq(group)) else {
        let seen = if groups.is_empty() {
            "no supported_groups extension".to_owned()
        } else {
            let groups: Vec<&str> = groups.iter().map(|group| bare(group)).collect();
            format!("groups: {}", groups.join(", "))
        };
        return Signal {
            label: LABEL,
            value: clean(&format!("No ({seen})")),
            tone: Some(Style::Yellow),
        };
    };
    let shared = extension(tls, "key_share")
        .and_then(|ext| ext["shared_keys"].as_array())
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .flat_map(|keys| keys.keys())
        .any(|name| !is_grease(name) && is_pq(name));
    let share = if shared {
        "key share sent"
    } else {
        "offered without a key share"
    };
    Signal {
        label: LABEL,
        value: clean(&format!("Yes ({}, {share})", bare(group))),
        tone: Some(Style::Green),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn check(id: &'static str, status: Status, title: &'static str, detail: &str) -> Check {
        Check {
            id,
            status,
            title,
            detail: detail.to_owned(),
            penalty: 0,
        }
    }

    fn tls() -> TlsDetails {
        TlsDetails {
            ciphers: vec![
                "TLS_GREASE (0xdada)".into(),
                "TLS_AES_128_GCM_SHA256".into(),
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".into(),
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into(),
            ],
            extensions: json!([
                { "name": "TLS_GREASE (0x0a0a) (2570)" },
                { "name": "server_name (0)", "server_name": "example.test" },
                { "name": "supported_groups (10)", "supported_groups": [
                    "GREASE (2570)", "X25519MLKEM768 (4588)", "X25519 (29)"] },
                { "name": "application_layer_protocol_negotiation (16)",
                  "protocols": ["h2", "http/1.1"] },
                { "name": "supported_versions (43)", "versions": ["GREASE (2570)", "TLS 1.3", "TLS 1.2"] },
                { "name": "key_share (51)", "shared_keys": [
                    { "X25519MLKEM768 (4588)": "00" }, { "X25519 (29)": "00" }] },
                { "name": "encrypted_client_hello (65037)" },
            ]),
            negotiated_version: 772,
            ja4: "t13d1517h2_8daaf6152771_cb7bf5808d99".into(),
            ja4_o: "t13d1517h2_8daaf6152771_aaaaaaaaaaaa".into(),
            ja3_hash: "375c6162a492dfbf2795909110ce8424".into(),
            peetprint_hash: "0d6ceceb9e71ec096d2022ad0651e2f2".into(),
            ..TlsDetails::default()
        }
    }

    fn http2_details() -> http2::Http2Details {
        let mut details = http2::Http2Details::default();
        details.akamai_fingerprint = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p".into();
        details.akamai_fingerprint_hash = "52d84b11737d980aef856699f885ca86".into();
        details
    }

    fn report() -> Report {
        Report {
            ip: "203.0.113.9:51234".into(),
            http_version: "h2".into(),
            tls: Some(tls()),
            http2: Some(http2_details()),
            ..Report::default()
        }
    }

    fn audit(checks: Vec<Check>) -> Audit {
        Audit {
            score: 55,
            verdict: Verdict::Inconsistent,
            checks,
        }
    }

    fn mixed() -> Audit {
        audit(vec![
            check(
                "a",
                Status::Pass,
                "TLS fingerprint against known clients",
                "Identical to Chrome 160",
            ),
            check(
                "b",
                Status::Fail,
                "Request headers of the claimed browser",
                "Chrome sends these with every request; missing here: sec-ch-ua, sec-fetch-*, accept-language, accept-encoding",
            ),
            check(
                "c",
                Status::Skip,
                "TCP stack against the User-Agent",
                "Not measured: no SYN",
            ),
            check(
                "d",
                Status::Warn,
                "HTTP/2 fingerprint against the client",
                "Unusual window",
            ),
            check(
                "e",
                Status::Fail,
                "User-Agent against the TLS stack",
                "The User-Agent says Chrome",
            ),
        ])
    }

    fn client() -> Value {
        json!({ "match": "exact", "family": "Chrome", "version": "160", "user_agent_family": "Chrome" })
    }

    /// The text with the six sequences of the renderer taken out.
    fn without_codes(text: &str) -> String {
        [RESET, BOLD, DIM, RED, GREEN, YELLOW]
            .iter()
            .fold(text.to_owned(), |text, code| text.replace(code, ""))
    }

    #[test]
    fn a_report_reads_top_down_with_problems_first() {
        let text = render_with(&report(), Some(&mixed()), &client(), Colour::Plain);
        let want = [
            "mirrust  (h2, TLS 1.3, 203.0.113.9:51234)",
            "",
            "AUDIT  55/100  [###########         ]  inconsistent",
            "  Looks like Chrome 160 (exact match). The User-Agent claims Chrome.",
            "",
            "  2 failed, 1 unusual, 1 passed, 1 not measured",
            "  [FAIL] Request headers of the claimed browser",
            "         Chrome sends these with every request; missing here: sec-ch-ua,",
            "         sec-fetch-*, accept-language, accept-encoding",
            "  [FAIL] User-Agent against the TLS stack",
            "         The User-Agent says Chrome",
            "  [WARN] HTTP/2 fingerprint against the client",
            "         Unusual window",
            "  [ ok ] TLS fingerprint against known clients",
            "         Identical to Chrome 160",
            "  [skip] TCP stack against the User-Agent",
            "         Not measured: no SYN",
            "",
            "FINGERPRINTS -----------------------------------------------------------------",
            "  ja4        t13d1517h2_8daaf6152771_cb7bf5808d99",
            "  ja4_o      t13d1517h2_8daaf6152771_aaaaaaaaaaaa",
            "  ja3        375c6162a492dfbf2795909110ce8424",
            "  peetprint  0d6ceceb9e71ec096d2022ad0651e2f2",
            "  akamai     52d84b11737d980aef856699f885ca86",
            "             1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
            "",
            "TLS --------------------------------------------------------------------------",
            "  Highest TLS version offered  TLS 1.3 (also 1.2)",
            "  Cipher suites                3",
            "  Extensions                   6",
            "  ALPN                         h2, http/1.1",
            "  Server name (SNI)            example.test",
            "  Post-quantum key exchange    Yes (X25519MLKEM768, key share sent)",
            "  Encrypted ClientHello        Sent",
            "  Legacy cipher suites         2 of 3 (1 broken)",
            "  GREASE                       Yes",
            "",
            "colour: ?color=1  JSON: /api/all  short JSON: /api/clean  page: /?format=html",
            "",
        ]
        .join("\n");
        assert_eq!(text, want);
    }

    #[test]
    fn plain_text_has_no_escape_codes_and_colour_adds_only_ours() {
        let report = report();
        let plain = render_with(&report, Some(&mixed()), &client(), Colour::Plain);
        let coloured = render_with(&report, Some(&mixed()), &client(), Colour::Ansi);
        assert!(!plain.contains('\x1b'));
        assert!(coloured.contains(RED) && coloured.contains(BOLD) && coloured.contains(DIM));
        let stripped = without_codes(&coloured);
        assert!(!stripped.contains('\x1b'), "{stripped:?}");
        assert_eq!(stripped, plain, "colour changes no character of the layout");
    }

    #[test]
    fn cipher_kinds_follow_forward_secrecy_and_mode() {
        let kind = |name: &str| cipher_kind(name);
        assert_eq!(kind("TLS_AES_128_GCM_SHA256"), None);
        assert_eq!(kind("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"), None);
        // Ephemeral key exchange keeps forward secrecy; the CBC mode alone is the weakness.
        let ecdhe_cbc = kind("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        assert_eq!(ecdhe_cbc, Some(CipherKind::Weak));
        for name in [
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
        ] {
            assert_eq!(kind(name), Some(CipherKind::Weak), "{name}");
        }
        assert_eq!(
            kind("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
            Some(CipherKind::Broken)
        );
    }

    #[test]
    fn an_ech_extension_is_not_praised_as_green() {
        // Chrome and Firefox send a GREASE ECH to a site with no ECH key, which hides nothing.
        let coloured = render_with(&report(), Some(&mixed()), &client(), Colour::Ansi);
        let line = coloured
            .lines()
            .find(|line| line.contains("Encrypted ClientHello"))
            .expect("the TLS block has the line");
        assert!(!line.contains(GREEN), "{line:?}");
    }

    #[test]
    fn colour_and_layout_by_verdict() {
        let ok = Audit {
            score: 100,
            verdict: Verdict::Consistent,
            checks: vec![check("a", Status::Pass, "t", "d")],
        };
        let text = render_with(&report(), Some(&ok), &client(), Colour::Ansi);
        assert!(
            text.contains(&format!("{GREEN}[####################]")),
            "{text}"
        );
        assert!(text.contains("1 check passed"));
        let odd = Audit {
            score: 70,
            verdict: Verdict::Suspicious,
            checks: vec![],
        };
        let text = render_with(&report(), Some(&odd), &client(), Colour::Plain);
        assert!(
            text.contains("[##############      ]  suspicious"),
            "{text}"
        );
        assert!(text.contains("no checks ran"));
    }

    #[test]
    fn checks_keep_their_order_within_a_status() {
        let text = render_with(&report(), Some(&mixed()), &client(), Colour::Plain);
        let badges: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("  ["))
            .map(|line| &line[2..8])
            .collect();
        assert_eq!(badges, ["[FAIL]", "[FAIL]", "[WARN]", "[ ok ]", "[skip]"]);
        let titles: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("  [FAIL]"))
            .map(|line| &line[9..])
            .collect();
        assert_eq!(
            titles,
            [
                "Request headers of the claimed browser",
                "User-Agent against the TLS stack"
            ]
        );
    }

    #[test]
    fn hostile_text_stays_ascii_short_and_inert() {
        let mut hostile = report();
        hostile.ip = format!("[::1]:1\n{}", "9".repeat(900));
        hostile.http_version = "h2\x1b[2J".into();
        let tls = hostile.tls.as_mut().expect("tls");
        tls.extensions = json!([{
            "name": "server_name (0)",
            "server_name": format!("\x1b[31m\n\r{}\u{202e}\u{e9}{}", "a".repeat(40), "b".repeat(3000)),
        }, {
            "name": "application_layer_protocol_negotiation (16)",
            "protocols": ["\x1b]0;pwned\x07", "x".repeat(500)],
        }]);
        let hostile_check = audit(vec![check(
            "a",
            Status::Fail,
            "Title",
            &format!("detail \x1b[2J\u{9b} {}", "z".repeat(400)),
        )]);
        for colour in [Colour::Plain, Colour::Ansi] {
            let text = render_with(&hostile, Some(&hostile_check), &client(), colour);
            let bare = without_codes(&text);
            assert!(
                !bare.contains(|c: char| !c.is_ascii() || (c.is_control() && c != '\n')),
                "{bare:?}"
            );
            for line in bare.lines() {
                assert!(line.len() <= WIDTH, "{} columns: {line}", line.len());
            }
            assert!(bare.contains("\\u{1b}[31m\\n\\r"), "{bare}");
            assert!(bare.contains("..."), "long client text is cut");
        }
    }

    #[test]
    fn wrapped_text_hangs_under_its_first_character() {
        let text = render_with(&report(), Some(&mixed()), &client(), Colour::Plain);
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|line| line.starts_with("  [FAIL] Request headers"))
            .expect("the check");
        assert_eq!(
            lines[at + 1],
            "         Chrome sends these with every request; missing here: sec-ch-ua,"
        );
        assert_eq!(
            lines[at + 2],
            "         sec-fetch-*, accept-language, accept-encoding"
        );

        assert_eq!(wrap("aa bb cc", 5), ["aa bb", "cc"]);
        assert_eq!(wrap("abcdefghij kl", 4), ["abcd", "efgh", "ij", "kl"]);
        assert_eq!(wrap("", 4), [""]);
        assert_eq!(wrap("exactly4 x", 8), ["exactly4", "x"]);
    }

    #[test]
    fn no_client_hello_gives_a_short_note() {
        let report = Report {
            ip: "[::1]:5".into(),
            http_version: "h2".into(),
            ..Report::default()
        };
        let text = render(&report, Colour::Plain);
        assert!(
            text.starts_with("mirrust  (h2, [::1]:5)\n\nNo TLS ClientHello was captured"),
            "{text}"
        );
        assert!(!text.contains("AUDIT") && !text.contains("FINGERPRINTS"));
        assert!(text.ends_with(&format!("{FOOTER}\n")));
    }

    #[test]
    fn the_footer_fits_the_width() {
        assert!(FOOTER.len() <= WIDTH);
    }

    #[test]
    fn http3_shows_its_fingerprint_instead_of_akamai() {
        let mut report = report();
        report.http2 = None;
        let mut details = http3::Http3Details::default();
        details.fingerprint = "1:100;6:65536|GREASE,2".into();
        details.fingerprint_hash = "00112233445566778899aabbccddeeff".into();
        report.http3 = Some(details);
        let text = render_with(&report, Some(&mixed()), &client(), Colour::Plain);
        assert!(text.contains("  http3      00112233445566778899aabbccddeeff\n             1:100;6:65536|GREASE,2\n"), "{text}");
        assert!(!text.contains("akamai"));
    }

    #[test]
    fn bare_drops_only_a_numeric_id() {
        assert_eq!(bare("X25519MLKEM768 (4588)"), "X25519MLKEM768");
        assert_eq!(bare("plain"), "plain");
        assert_eq!(bare("name (abc)"), "name (abc)");
    }
}
