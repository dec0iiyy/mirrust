//! `fpdiff`: compares two client fingerprints and exits 0 when they are equivalent, 1 when
//! they differ and 2 on bad input.

use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result};
use clap::Parser;
use fpdiff::{Options, Profile, Section, compare};

/// Compare a client's TLS (and HTTP/2) fingerprint with a reference one.
///
/// Each input is tls.peet.ws JSON (`/api/all`, `/api/tls`, or the bare `tls` object) or a
/// ClientHello as hex (handshake message or full TLS record); `-` reads stdin. In the report,
/// `-` lines are only in the reference and `+` lines only in the candidate. Exit status: 0
/// equivalent, 1 different, 2 bad input.
#[derive(Debug, Parser)]
#[command(name = "fpdiff", version)]
struct Cli {
    /// The reference fingerprint, e.g. a capture of the real browser.
    reference: PathBuf,
    /// The fingerprint to check, e.g. your client's.
    candidate: PathBuf,
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
    /// Also report a different extension order (Chrome shuffles it per connection).
    #[arg(long)]
    strict_order: bool,
    /// Sections to skip, comma-separated or repeated; `http2` skips every HTTP/2 section.
    #[arg(long, value_delimiter = ',', value_name = "SECTION")]
    ignore: Vec<String>,
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("fpdiff: {error:#}");
            ExitCode::from(2)
        }
    }
}

/// Prints the report and returns whether the inputs are equivalent.
fn run(cli: &Cli) -> Result<bool> {
    let options = Options {
        strict_order: cli.strict_order,
        ignore: ignored_sections(&cli.ignore)?,
    };
    let reference = read_profile(&cli.reference)?;
    let candidate = read_profile(&cli.candidate)?;
    let report = compare(&reference, &candidate, &options);
    if cli.json {
        println!("{:#}", report.to_json());
    } else {
        println!("{report}");
    }
    Ok(report.is_equivalent())
}

fn ignored_sections(names: &[String]) -> Result<BTreeSet<Section>> {
    let mut sections = BTreeSet::new();
    for name in names {
        if name.trim().eq_ignore_ascii_case("http2") {
            sections.extend(
                Section::ALL
                    .into_iter()
                    .filter(|section| section.name().starts_with("http2")),
            );
        } else {
            sections.insert(name.parse::<Section>()?);
        }
    }
    Ok(sections)
}

fn read_profile(path: &Path) -> Result<Profile> {
    let text = if path.as_os_str() == "-" {
        let mut text = String::new();
        io::stdin()
            .read_to_string(&mut text)
            .context("reading stdin")?;
        text
    } else {
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?
    };
    Profile::parse(&text).with_context(|| format!("reading {}", path.display()))
}
