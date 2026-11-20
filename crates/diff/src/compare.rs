//! Section-by-section comparison of two [`Profile`]s.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde_json::{Value, json};

use crate::{
    Profile,
    http2::{Akamai, setting_name},
    profile::{ALPS, ALPS_OLD},
};

/// One part of the fingerprint that is compared on its own and can be ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Section {
    /// `legacy_version` and `supported_versions`, in order.
    Versions,
    /// Cipher suites: set and order.
    Ciphers,
    /// Extension set; the order only with [`Options::strict_order`].
    Extensions,
    /// `supported_groups`, in order.
    Groups,
    /// Groups with a key share, in order.
    KeyShare,
    /// `signature_algorithms`, in order.
    SignatureAlgorithms,
    /// ALPN protocols, in order.
    Alpn,
    /// `ec_point_formats`.
    PointFormats,
    /// `psk_key_exchange_modes`.
    PskModes,
    /// `compress_certificate` algorithms.
    CertCompression,
    /// `record_size_limit` value.
    RecordSizeLimit,
    /// Whether `encrypted_client_hello` is sent.
    Ech,
    /// ALPS codepoint (17513 or 17613) and protocols.
    Alps,
    /// HTTP/2 SETTINGS: ids, values, order.
    Http2Settings,
    /// HTTP/2 connection `WINDOW_UPDATE`.
    Http2WindowUpdate,
    /// HTTP/2 PRIORITY frames.
    Http2Priority,
    /// HTTP/2 pseudo-header order.
    Http2PseudoHeaders,
}

impl Section {
    /// Every section, in report order.
    pub const ALL: [Self; 17] = [
        Self::Versions,
        Self::Ciphers,
        Self::Extensions,
        Self::Groups,
        Self::KeyShare,
        Self::SignatureAlgorithms,
        Self::Alpn,
        Self::PointFormats,
        Self::PskModes,
        Self::CertCompression,
        Self::RecordSizeLimit,
        Self::Ech,
        Self::Alps,
        Self::Http2Settings,
        Self::Http2WindowUpdate,
        Self::Http2Priority,
        Self::Http2PseudoHeaders,
    ];

    /// The name used in reports and by `--ignore`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Versions => "versions",
            Self::Ciphers => "ciphers",
            Self::Extensions => "extensions",
            Self::Groups => "groups",
            Self::KeyShare => "key_share",
            Self::SignatureAlgorithms => "signature_algorithms",
            Self::Alpn => "alpn",
            Self::PointFormats => "point_formats",
            Self::PskModes => "psk_modes",
            Self::CertCompression => "cert_compression",
            Self::RecordSizeLimit => "record_size_limit",
            Self::Ech => "ech",
            Self::Alps => "alps",
            Self::Http2Settings => "http2_settings",
            Self::Http2WindowUpdate => "http2_window_update",
            Self::Http2Priority => "http2_priority",
            Self::Http2PseudoHeaders => "http2_pseudo_headers",
        }
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A section name that [`Section::from_str`] does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSectionError(String);

impl fmt::Display for ParseSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = Section::ALL.iter().map(|s| s.name()).collect();
        write!(
            f,
            "unknown section {:?}; known: {}",
            self.0,
            names.join(", ")
        )
    }
}

impl std::error::Error for ParseSectionError {}

impl FromStr for Section {
    type Err = ParseSectionError;

    /// Parses a section name; `-` and `_` are interchangeable.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let wanted = text.trim().to_ascii_lowercase().replace('-', "_");
        Self::ALL
            .into_iter()
            .find(|section| section.name() == wanted)
            .ok_or_else(|| ParseSectionError(text.to_owned()))
    }
}

/// What [`compare`] treats as a difference.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Report a different extension order. Off by default, since Chrome shuffles extensions
    /// on every connection.
    pub strict_order: bool,
    /// Sections to skip.
    pub ignore: BTreeSet<Section>,
}

/// One difference inside a section; the first input is the reference.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// Only the reference has this item.
    Removed(String),
    /// Only the candidate has this item.
    Added(String),
    /// A single value differs.
    Changed {
        /// The reference's value.
        from: String,
        /// The candidate's value.
        to: String,
    },
    /// Both have the same items in a different order (common items only).
    Order {
        /// The reference's order.
        from: Vec<String>,
        /// The candidate's order.
        to: Vec<String>,
    },
}

impl Change {
    fn to_json(&self) -> Value {
        match self {
            Self::Removed(item) => json!({ "op": "-", "value": item }),
            Self::Added(item) => json!({ "op": "+", "value": item }),
            Self::Changed { from, to } => json!({ "op": "changed", "from": from, "to": to }),
            Self::Order { from, to } => json!({ "op": "order", "from": from, "to": to }),
        }
    }
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Removed(item) => write!(f, "  - {item}"),
            Self::Added(item) => write!(f, "  + {item}"),
            Self::Changed { from, to } => write!(f, "  - {from}\n  + {to}"),
            Self::Order { from, to } => write!(
                f,
                "  ~ order\n    - {}\n    + {}",
                from.join(" "),
                to.join(" ")
            ),
        }
    }
}

/// The differences in one section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionDiff {
    /// The section.
    pub section: Section,
    /// What differs; never empty.
    pub changes: Vec<Change>,
}

/// The JA4 (FoxIO spec) of both inputs and which of its parts match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Comparison {
    /// The reference's JA4.
    pub reference: String,
    /// The candidate's JA4.
    pub candidate: String,
    /// Whether parts a, b and c match.
    pub parts_match: [bool; 3],
}

/// The result of [`compare`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Sections that differ, in [`Section::ALL`] order.
    pub sections: Vec<SectionDiff>,
    /// JA4 of both inputs, for information; it follows from the sections.
    pub ja4: Ja4Comparison,
    /// Things that were not compared, such as HTTP/2 present in one input only.
    pub notes: Vec<String>,
}

impl Report {
    /// Whether no compared section differs.
    #[must_use]
    pub fn is_equivalent(&self) -> bool {
        self.sections.is_empty()
    }

    /// The one-line verdict.
    #[must_use]
    pub fn verdict(&self) -> String {
        if self.is_equivalent() {
            "equivalent".to_owned()
        } else {
            let names: Vec<&str> = self.sections.iter().map(|s| s.section.name()).collect();
            format!(
                "different: {} section(s) differ ({})",
                names.len(),
                names.join(", ")
            )
        }
    }

    /// The report as JSON for machines.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let differences: serde_json::Map<String, Value> = self
            .sections
            .iter()
            .map(|diff| {
                let changes = diff.changes.iter().map(Change::to_json).collect();
                (diff.section.name().to_owned(), Value::Array(changes))
            })
            .collect();
        let [a, b, c] = self.ja4.parts_match;
        json!({
            "equivalent": self.is_equivalent(),
            "verdict": self.verdict(),
            "ja4": {
                "reference": self.ja4.reference,
                "candidate": self.ja4.candidate,
                "a": a,
                "b": b,
                "c": c,
            },
            "differences": differences,
            "notes": self.notes,
        })
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verdict = |same: bool| if same { "match" } else { "differ" };
        let [a, b, c] = self.ja4.parts_match;
        writeln!(f, "JA4 reference: {}", self.ja4.reference)?;
        writeln!(f, "JA4 candidate: {}", self.ja4.candidate)?;
        writeln!(
            f,
            "JA4 parts: a {}, b {}, c {}",
            verdict(a),
            verdict(b),
            verdict(c)
        )?;
        for diff in &self.sections {
            writeln!(f, "\n[{}]", diff.section)?;
            for change in &diff.changes {
                writeln!(f, "{change}")?;
            }
        }
        for note in &self.notes {
            writeln!(f, "\nnote: {note}")?;
        }
        write!(f, "\n{}", self.verdict())
    }
}

/// Compares a reference fingerprint with a candidate, section by section.
#[must_use]
pub fn compare(reference: &Profile, candidate: &Profile, options: &Options) -> Report {
    let (a, b) = (reference, candidate);
    let mut notes = Vec::new();
    let http2 = match (&a.http2, &b.http2) {
        (Some(a), Some(b)) => Some((a, b)),
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => {
            let which = if a.http2.is_some() {
                "reference"
            } else {
                "candidate"
            };
            notes.push(format!(
                "only the {which} has an HTTP/2 fingerprint; HTTP/2 not compared"
            ));
            None
        }
    };

    let sections = Section::ALL
        .into_iter()
        .filter(|section| !options.ignore.contains(section))
        .map(|section| SectionDiff {
            section,
            changes: section_changes(section, a, b, http2, options),
        })
        .filter(|diff| !diff.changes.is_empty())
        .collect();

    let (ja4_a, ja4_b) = (a.ja4(), b.ja4());
    let parts = |ja4: &str| -> Vec<String> { ja4.split('_').map(str::to_owned).collect() };
    let (parts_a, parts_b) = (parts(ja4_a.hashed()), parts(ja4_b.hashed()));
    let part_match = |i: usize| parts_a.get(i) == parts_b.get(i);
    Report {
        sections,
        ja4: Ja4Comparison {
            reference: ja4_a.hashed().to_owned(),
            candidate: ja4_b.hashed().to_owned(),
            parts_match: [part_match(0), part_match(1), part_match(2)],
        },
        notes,
    }
}

fn section_changes(
    section: Section,
    a: &Profile,
    b: &Profile,
    http2: Option<(&Akamai, &Akamai)>,
    options: &Options,
) -> Vec<Change> {
    match section {
        Section::Http2Settings
        | Section::Http2WindowUpdate
        | Section::Http2Priority
        | Section::Http2PseudoHeaders => {
            http2.map_or_else(Vec::new, |(a, b)| http2_changes(section, a, b))
        }
        Section::Versions
        | Section::PskModes
        | Section::RecordSizeLimit
        | Section::Ech
        | Section::Alps => value_section_changes(section, a, b),
        _ => list_section_changes(section, a, b, options),
    }
}

/// The display name the inputs carried for `id`, else `fallback`.
fn named(
    names_a: &BTreeMap<u16, String>,
    names_b: &BTreeMap<u16, String>,
    id: u16,
    fallback: String,
) -> String {
    names_a
        .get(&id)
        .or_else(|| names_b.get(&id))
        .cloned()
        .unwrap_or(fallback)
}

fn hex(id: u16) -> String {
    format!("{id:04x}")
}

fn list_section_changes(
    section: Section,
    a: &Profile,
    b: &Profile,
    options: &Options,
) -> Vec<Change> {
    let group = |&id: &u16| {
        named(
            &a.names.groups,
            &b.names.groups,
            id,
            format!("group ({id})"),
        )
    };
    let decimal = u16::to_string;
    match section {
        Section::Ciphers => list_changes(
            &a.ciphers,
            &b.ciphers,
            Order::Matters,
            |&id| {
                let name = named(&a.names.ciphers, &b.names.ciphers, id, String::new());
                format!("{name} (0x{id:04x})").trim_start().to_owned()
            },
            |&id| hex(id),
        ),
        Section::Extensions => list_changes(
            &a.extensions,
            &b.extensions,
            if options.strict_order {
                Order::Matters
            } else {
                Order::Ignored
            },
            |&id| {
                let fallback = format!("extension ({id})");
                named(&a.names.extensions, &b.names.extensions, id, fallback)
            },
            decimal,
        ),
        Section::Groups => list_changes(&a.groups, &b.groups, Order::Matters, group, decimal),
        Section::KeyShare => list_changes(
            &a.key_share_groups,
            &b.key_share_groups,
            Order::Matters,
            group,
            decimal,
        ),
        Section::SignatureAlgorithms => list_changes(
            &a.signature_algorithms,
            &b.signature_algorithms,
            Order::Matters,
            |&id| {
                let name = named(&a.names.signatures, &b.names.signatures, id, String::new());
                format!("{name} (0x{id:04x})").trim_start().to_owned()
            },
            |&id| hex(id),
        ),
        Section::Alpn => list_changes(&a.alpn, &b.alpn, Order::Matters, Clone::clone, Clone::clone),
        Section::PointFormats => {
            let label = |format: &u8| format!("0x{format:02x}");
            list_changes(
                &a.point_formats,
                &b.point_formats,
                Order::Matters,
                label,
                label,
            )
        }
        Section::CertCompression => list_changes(
            &a.cert_compression,
            &b.cert_compression,
            Order::Matters,
            |&id| compression_name(id),
            decimal,
        ),
        _ => Vec::new(),
    }
}

fn value_section_changes(section: Section, a: &Profile, b: &Profile) -> Vec<Change> {
    match section {
        Section::Versions => {
            let mut changes = value_change(
                &version_name(a.legacy_version),
                &version_name(b.legacy_version),
            );
            changes.extend(list_changes(
                &a.versions,
                &b.versions,
                Order::Matters,
                |v| format!("supported {}", version_name(*v)),
                |&id| hex(id),
            ));
            changes
        }
        Section::PskModes => value_change(&psk_name(a.psk_mode), &psk_name(b.psk_mode)),
        Section::RecordSizeLimit => {
            let show = |limit: Option<u16>| {
                limit.map_or_else(|| "absent".to_owned(), |value| value.to_string())
            };
            value_change(&show(a.record_size_limit), &show(b.record_size_limit))
        }
        Section::Ech => {
            let show = |ech: bool| if ech { "sent" } else { "absent" }.to_owned();
            value_change(&show(a.ech()), &show(b.ech()))
        }
        Section::Alps => {
            let mut changes = value_change(&alps_name(a.alps()), &alps_name(b.alps()));
            changes.extend(list_changes(
                &a.alps_protocols,
                &b.alps_protocols,
                Order::Matters,
                |name| format!("protocol {name}"),
                Clone::clone,
            ));
            changes
        }
        _ => Vec::new(),
    }
}

fn http2_changes(section: Section, a: &Akamai, b: &Akamai) -> Vec<Change> {
    match section {
        Section::Http2Settings => settings_changes(a, b),
        Section::Http2WindowUpdate => value_change(&a.window_update, &b.window_update),
        Section::Http2Priority => value_change(&a.priority, &b.priority),
        Section::Http2PseudoHeaders => {
            value_change(&a.pseudo_headers.join(","), &b.pseudo_headers.join(","))
        }
        _ => Vec::new(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    Matters,
    Ignored,
}

/// `-` for items only in `a`, `+` for items only in `b`, then an order line when the
/// common items come in a different order and the order matters.
fn list_changes<T: PartialEq>(
    a: &[T],
    b: &[T],
    order: Order,
    label: impl Fn(&T) -> String,
    short: impl Fn(&T) -> String,
) -> Vec<Change> {
    let mut changes: Vec<Change> = a
        .iter()
        .filter(|item| !b.contains(item))
        .map(|item| Change::Removed(label(item)))
        .collect();
    changes.extend(
        b.iter()
            .filter(|item| !a.contains(item))
            .map(|item| Change::Added(label(item))),
    );
    if order == Order::Matters {
        let common_a: Vec<&T> = a.iter().filter(|item| b.contains(item)).collect();
        let common_b: Vec<&T> = b.iter().filter(|item| a.contains(item)).collect();
        if common_a != common_b {
            changes.push(Change::Order {
                from: common_a.into_iter().map(&short).collect(),
                to: common_b.into_iter().map(&short).collect(),
            });
        }
    }
    changes
}

fn value_change(a: &str, b: &str) -> Vec<Change> {
    if a == b {
        Vec::new()
    } else {
        vec![Change::Changed {
            from: a.to_owned(),
            to: b.to_owned(),
        }]
    }
}

/// SETTINGS: ids only on one side, changed values, then the order of the common ids.
fn settings_changes(a: &Akamai, b: &Akamai) -> Vec<Change> {
    let value_of = |settings: &[(u16, u64)], id: u16| {
        settings
            .iter()
            .find(|(setting, _)| *setting == id)
            .map(|&(_, value)| value)
    };
    let ids = |akamai: &Akamai| -> Vec<u16> { akamai.settings.iter().map(|&(id, _)| id).collect() };
    let mut changes = list_changes(
        &ids(a),
        &ids(b),
        Order::Matters,
        |&id| {
            let value = value_of(&a.settings, id)
                .or_else(|| value_of(&b.settings, id))
                .unwrap_or_default();
            format!("{} = {value}", setting_name(id))
        },
        u16::to_string,
    );
    for &(id, from) in &a.settings {
        if let Some(to) = value_of(&b.settings, id).filter(|&to| to != from) {
            changes.push(Change::Changed {
                from: format!("{} = {from}", setting_name(id)),
                to: format!("{} = {to}", setting_name(id)),
            });
        }
    }
    changes
}

fn version_name(version: u16) -> String {
    let name = match version {
        0x0304 => "TLS 1.3",
        0x0303 => "TLS 1.2",
        0x0302 => "TLS 1.1",
        0x0301 => "TLS 1.0",
        _ => "version",
    };
    format!("{name} (0x{version:04x})")
}

fn psk_name(mode: Option<u8>) -> String {
    match mode {
        None => "absent".to_owned(),
        Some(0) => "psk_ke (0)".to_owned(),
        Some(1) => "psk_dhe_ke (1)".to_owned(),
        Some(other) => format!("mode ({other})"),
    }
}

fn compression_name(id: u16) -> String {
    let name = match id {
        1 => "zlib",
        2 => "brotli",
        3 => "zstd",
        _ => "algorithm",
    };
    format!("{name} ({id})")
}

fn alps_name(id: Option<u16>) -> String {
    match id {
        Some(ALPS_OLD) => format!("application_settings_old ({ALPS_OLD})"),
        Some(ALPS) => format!("application_settings ({ALPS})"),
        Some(other) => format!("extension ({other})"),
        None => "absent".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_names_round_trip() {
        for section in Section::ALL {
            assert_eq!(section.name().parse(), Ok(section));
        }
        assert_eq!("key-share".parse(), Ok(Section::KeyShare));
        assert!("nope".parse::<Section>().is_err());
    }

    #[test]
    fn lists_report_missing_extra_and_order() {
        let changes = list_changes(
            &[1, 2, 3],
            &[3, 2, 4],
            Order::Matters,
            u16::to_string,
            u16::to_string,
        );
        assert_eq!(
            changes,
            [
                Change::Removed("1".into()),
                Change::Added("4".into()),
                Change::Order {
                    from: vec!["2".into(), "3".into()],
                    to: vec!["3".into(), "2".into()],
                },
            ]
        );
    }
}
