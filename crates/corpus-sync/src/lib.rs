//! Proposes new `corpus/clients.jsonl` lines from curl-impersonate's test signatures.
//!
//! Each captured signature (`tests/signatures/*.yaml` without `partial: true`) is turned into
//! a ClientHello and a list of HTTP/2 frames, which this workspace's `fingerprint` and `http2`
//! crates hash. Signatures whose JA4 the dataset lacks become new lines, one per JA4; the
//! others are only reported. Existing lines are never changed.

mod signature;
mod yaml;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Value, json};

pub use signature::{Signature, Skip};

/// The outcome of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// New dataset lines, in the dataset's format, one per JA4 the dataset lacks.
    pub new_lines: Vec<String>,
    /// One message per signature whose JA4 the dataset already has.
    pub known: Vec<String>,
    /// One message per signature that yields no entry, with the reason.
    pub skipped: Vec<String>,
}

/// The `pre_shared_key` extension as `ja4_r` writes it; it marks a resumed connection.
const PRE_SHARED_KEY: &str = "0029";

struct Found {
    file: String,
    signature: Signature,
}

/// Reads every signature in `signatures` (curl-impersonate's `tests/signatures`) and compares
/// it with `dataset`, the text of `corpus/clients.jsonl`. `commit` names the upstream commit in
/// the `source` of new lines.
///
/// # Errors
///
/// Returns an error when the directory cannot be read or a dataset line is not JSON. A
/// signature that cannot be parsed or hashed is reported in [`Report::skipped`] instead.
pub fn sync(signatures: &Path, commit: &str, dataset: &str) -> Result<Report> {
    let known = known_ja4s(dataset)?;
    let mut files: Vec<_> = fs::read_dir(signatures)
        .with_context(|| format!("reading {}", signatures.display()))?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    files.retain(|path| path.extension().is_some_and(|ext| ext == "yaml"));
    files.sort();

    let mut report = Report::default();
    let mut found = Vec::new();
    for path in files {
        let file = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = fs::read_to_string(&path).with_context(|| format!("reading {file}"))?;
        let signature = yaml::parse(&text)
            .map_err(|error| Skip::Incomplete(format!("{error:#}")))
            .and_then(|doc| Signature::from_value(&doc));
        match signature {
            Ok(signature) => match known.get(&signature.ja4) {
                Some(entry) => report.known.push(format!(
                    "{file}: {} {} already known (could widen the version range of {entry})",
                    signature.browser, signature.version
                )),
                None => found.push(Found { file, signature }),
            },
            Err(Skip::Partial) => report.skipped.push(format!("{file}: partial, skipped")),
            Err(Skip::Incomplete(why)) => {
                report
                    .skipped
                    .push(format!("{file}: not enough detail ({why})"));
            }
        }
    }

    let mut groups: Vec<Vec<Found>> = Vec::new();
    for item in found {
        match groups
            .iter_mut()
            .find(|group| group[0].signature.ja4 == item.signature.ja4)
        {
            Some(group) => group.push(item),
            None => groups.push(vec![item]),
        }
    }
    for group in &mut groups {
        group.sort_by_key(|item| version_key(&item.signature.version));
    }
    groups.sort_by_key(|group| {
        (
            family(&group[0].signature.browser).0,
            version_key(&group[0].signature.version),
        )
    });
    report.new_lines = groups
        .iter()
        .map(|group| entry(group, commit).to_string())
        .collect();
    Ok(report)
}

/// The dataset's JA4s, each with the `family version` of its line.
fn known_ja4s(dataset: &str) -> Result<HashMap<String, String>> {
    dataset
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(n, line)| {
            let value: Value = serde_json::from_str(line)
                .with_context(|| format!("dataset line {} is not JSON", n + 1))?;
            let text = |key: &str| value[key].as_str().unwrap_or_default().to_owned();
            Ok((
                text("ja4"),
                format!("{} {}", text("family"), text("version")),
            ))
        })
        .collect()
}

/// The dataset's `family` and `library` for a curl-impersonate browser name.
fn family(browser: &str) -> (String, Option<&'static str>) {
    match browser {
        "chrome" => ("Chrome".to_owned(), Some("BoringSSL")),
        "edge" => ("Edge".to_owned(), Some("BoringSSL")),
        "firefox" => ("Firefox".to_owned(), Some("NSS")),
        "tor" => ("Tor Browser".to_owned(), Some("NSS")),
        "safari" => ("Safari".to_owned(), None),
        other => {
            let mut chars = other.chars();
            let name = chars
                .next()
                .map(|c| c.to_uppercase().chain(chars).collect())
                .unwrap_or_default();
            (name, None)
        }
    }
}

fn major(version: &str) -> Option<u32> {
    version.split('.').next()?.parse().ok()
}

fn version_key(version: &str) -> Vec<u32> {
    version
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

fn joined(items: &[String], last: &str) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., tail] => format!("{} {last} {tail}", init.join(", ")),
    }
}

/// One dataset line for signatures that share a JA4, sorted by version.
fn entry(group: &[Found], commit: &str) -> Value {
    let first = &group[0].signature;
    let newest = &group[group.len() - 1].signature;
    let (family, library) = family(&first.browser);
    // A JA4 shared by two browsers (Chrome and Edge) names each version's browser.
    let mixed = group.iter().any(|f| f.signature.browser != first.browser);
    let versions: Vec<String> = group
        .iter()
        .map(|f| {
            let version = &f.signature.version;
            if mixed {
                format!("{} {version}", self::family(&f.signature.browser).0)
            } else {
                version.clone()
            }
        })
        .collect();
    let (min, max) = (major(&first.version), major(&newest.version));
    let range = match (min, max) {
        (Some(min), Some(max)) if min != max => format!("{min}-{max}"),
        (Some(min), _) => min.to_string(),
        _ => first.version.clone(),
    };
    let mut oses: Vec<String> = Vec::new();
    for item in group {
        if !item.signature.os.is_empty() && !oses.contains(&item.signature.os) {
            oses.push(item.signature.os.clone());
        }
    }
    let files: Vec<String> = group
        .iter()
        .map(|f| format!("tests/signatures/{}", f.file))
        .collect();
    let who = if mixed {
        joined(&versions, "and")
    } else {
        format!("{family} {}", joined(&versions, "and"))
    };
    let mut source = format!(
        "curl-impersonate {} (lexiforest/curl-impersonate {commit}, MIT), {who}",
        files.join(", "),
    );
    if !oses.is_empty() {
        let _ = write!(source, " on {}", joined(&oses, "and"));
    }
    if newest.akamai.is_some() {
        source.push_str(", HTTP/2");
    }
    source.push_str("; JA4 derived from a ClientHello rebuilt from the signature");
    let extensions = first.ja4_r.split('_').nth(2).unwrap_or_default();
    if extensions.split(',').any(|kind| kind == PRE_SHARED_KEY) {
        source.push_str("; the hello resumes a session (pre_shared_key)");
    }
    if group.iter().any(|f| f.signature.akamai != newest.akamai) {
        let _ = write!(
            source,
            "; the akamai value is the one of {}",
            newest.version
        );
    }
    json!({
        "family": family,
        "version": format!("{range} ({})", versions.join(", ")),
        "version_min": min,
        "version_max": max,
        "library": library,
        "source": source,
        "ja4": first.ja4,
        "ja4_r": first.ja4_r,
        "akamai": newest.akamai,
    })
}
