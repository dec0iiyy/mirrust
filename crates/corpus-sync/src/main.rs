//! `corpus-sync`: prints, as JSON Lines, the `crates/fingerprint/data/clients.jsonl` entries that
//! curl-impersonate's captured test signatures add.
//!
//! ```console
//! $ cargo run -p corpus-sync -- path/to/curl-impersonate [crates/fingerprint/data/clients.jsonl]
//! ```
//!
//! New lines go to stdout; signatures the dataset already has, and skipped ones, to stderr.

use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::{env, fs};

use anyhow::{Context, Result, bail};

fn upstream_commit(checkout: &PathBuf) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .context("running git")?;
    if !output.status.success() {
        bail!("{} is not a git checkout", checkout.display());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let Some(checkout) = args.next().map(PathBuf::from) else {
        bail!("usage: corpus-sync <curl-impersonate checkout> [clients.jsonl]");
    };
    let dataset_path = args.next().map_or_else(
        || PathBuf::from("crates/fingerprint/data/clients.jsonl"),
        PathBuf::from,
    );
    let dataset = fs::read_to_string(&dataset_path)
        .with_context(|| format!("reading {}", dataset_path.display()))?;
    let commit = upstream_commit(&checkout)?;
    let report = corpus_sync::sync(&checkout.join("tests/signatures"), &commit, &dataset)?;
    for line in &report.skipped {
        eprintln!("{line}");
    }
    for line in &report.known {
        eprintln!("{line}");
    }
    eprintln!(
        "{} new, {} already known, {} skipped (lexiforest/curl-impersonate {commit})",
        report.new_lines.len(),
        report.known.len(),
        report.skipped.len()
    );
    for line in &report.new_lines {
        println!("{line}");
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("corpus-sync: {error:#}");
            ExitCode::FAILURE
        }
    }
}
