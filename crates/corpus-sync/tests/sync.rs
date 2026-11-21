//! Runs the sync against a copy of one curl-impersonate signature (`fixtures/`, MIT, see
//! `LICENSE-curl-impersonate` there) and the real dataset.

use std::path::Path;

use serde_json::Value;

const DATASET: &str = include_str!("../../../corpus/clients.jsonl");
const COMMIT: &str = "5b1c354";

fn signatures() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tests/signatures"
    ))
}

fn dataset_line(ja4: &str) -> Value {
    DATASET
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("dataset lines are JSON"))
        .find(|entry| entry["ja4"] == ja4)
        .unwrap_or_else(|| panic!("no dataset line with ja4 {ja4}"))
}

#[test]
fn known_signature_adds_nothing() {
    let report = corpus_sync::sync(signatures(), COMMIT, DATASET).expect("the fixtures sync");
    assert!(report.new_lines.is_empty(), "{:?}", report.new_lines);
    assert_eq!(report.known.len(), 1, "{:?}", report.known);
    assert!(
        report.known[0].contains("already known (could widen the version range of Chrome 150"),
        "{}",
        report.known[0]
    );
    assert_eq!(report.skipped, ["chrome152.yaml: partial, skipped"]);
}

#[test]
fn empty_dataset_regenerates_the_entry() {
    let report = corpus_sync::sync(signatures(), COMMIT, "").expect("the fixtures sync");
    assert_eq!(report.new_lines.len(), 1, "{:?}", report.new_lines);
    let new: Value = serde_json::from_str(&report.new_lines[0]).expect("the new line is JSON");
    let want = dataset_line("t13d1516h2_8daaf6152771_806a8c22fdea");
    // Every key in the dataset's order; the free-text `source` names the same file and commit.
    let keys = |v: &Value| v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>());
    assert_eq!(keys(&new), keys(&want));
    // The fingerprints and the family are what the tool derives. The version range of a dataset
    // line is widened by hand when another browser sends the same hello, so it is checked
    // against the fixture's own file name instead.
    for key in ["family", "library", "ja4", "ja4_r", "akamai"] {
        assert_eq!(new[key], want[key], "key {key}");
    }
    assert_eq!(new["version"], "150 (150.0.7871.127)");
    assert_eq!(new["version_min"], 150);
    assert_eq!(new["version_max"], 150);
    let source = new["source"].as_str().unwrap_or_default();
    assert!(
        source.starts_with(
            "curl-impersonate tests/signatures/chrome_150.0.7871.127_macOS.yaml \
             (lexiforest/curl-impersonate 5b1c354, MIT)"
        ),
        "{source}"
    );
}
