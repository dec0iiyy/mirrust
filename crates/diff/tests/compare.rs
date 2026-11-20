//! `fpdiff` on the utls corpus: tls.peet.ws-style JSON (`corpus/expected.jsonl`) and raw hellos
//! (`corpus/hellos.jsonl`).

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use fingerprint::{ClientHello, Ja4, Transport};
use fpdiff::{Change, Options, Profile, Report, Section, compare};
use serde_json::{Value, json};

fn corpus(file: &str) -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(file);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
        .lines()
        .map(|line| serde_json::from_str(line).expect("corpus lines are JSON"))
        .collect()
}

fn entry(file: &str, name: &str) -> Value {
    corpus(file)
        .into_iter()
        .find(|line| line["name"] == name)
        .unwrap_or_else(|| panic!("{name} is not in {file}"))
}

/// The tls.peet.ws JSON of a corpus hello.
fn json(name: &str) -> Value {
    entry("expected.jsonl", name)
}

fn hex(name: &str) -> String {
    entry("hellos.jsonl", name)["hex"]
        .as_str()
        .expect("hex is a string")
        .to_owned()
}

fn profile(value: &Value) -> Profile {
    Profile::from_json(value).expect("corpus JSON reads")
}

fn diff(reference: &str, candidate: &str) -> Report {
    compare(
        &profile(&json(reference)),
        &profile(&json(candidate)),
        &Options::default(),
    )
}

fn sections(report: &Report) -> Vec<Section> {
    report.sections.iter().map(|diff| diff.section).collect()
}

fn changes(report: &Report, section: Section) -> Vec<Change> {
    report
        .sections
        .iter()
        .find(|diff| diff.section == section)
        .map(|diff| diff.changes.clone())
        .unwrap_or_default()
}

fn decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("corpus hex is valid"))
        .collect()
}

/// Writes a ClientHello handshake message back out.
fn encode(hello: &ClientHello) -> Vec<u8> {
    let len16 = |data: &[u8]| {
        let len = u16::try_from(data.len()).expect("fits in u16");
        [&len.to_be_bytes()[..], data].concat()
    };
    let ciphers: Vec<u8> = hello
        .cipher_suites
        .iter()
        .flat_map(|c| c.to_be_bytes())
        .collect();
    let extensions: Vec<u8> = hello
        .extensions
        .iter()
        .flat_map(|e| [&e.kind.to_be_bytes()[..], &len16(&e.data)].concat())
        .collect();
    let session_len = u8::try_from(hello.session_id.len()).expect("fits in u8");
    let compression_len = u8::try_from(hello.compression_methods.len()).expect("fits in u8");
    let body = [
        &hello.legacy_version.to_be_bytes()[..],
        &hello.random,
        &[session_len],
        &hello.session_id,
        &len16(&ciphers),
        &[compression_len],
        &hello.compression_methods,
        &len16(&extensions),
    ]
    .concat();
    let len = u32::try_from(body.len())
        .expect("fits in u32")
        .to_be_bytes();
    [&[1, len[1], len[2], len[3]][..], &body].concat()
}

#[test]
fn identical_inputs_are_equivalent() {
    for line in corpus("expected.jsonl") {
        let report = compare(&profile(&line), &profile(&line), &Options::default());
        assert!(report.is_equivalent(), "{}: {report}", line["name"]);
        assert_eq!(report.ja4.parts_match, [true; 3]);
    }
}

#[test]
fn hex_and_json_of_one_hello_are_equivalent() {
    let options = Options {
        strict_order: true,
        ..Options::default()
    };
    let expected = corpus("expected.jsonl");
    for (hello, json) in corpus("hellos.jsonl").iter().zip(&expected) {
        assert_eq!(hello["name"], json["name"]);
        let from_hex = Profile::parse(hello["hex"].as_str().expect("hex")).expect("hex reads");
        let report = compare(&from_hex, &profile(json), &options);
        assert!(report.is_equivalent(), "{}: {report}", json["name"]);
    }
}

/// The profile keeps everything JA4 reads: its JA4 equals the one computed from the bytes.
#[test]
fn profile_ja4_matches_the_hello() {
    for line in corpus("hellos.jsonl") {
        let hex = line["hex"].as_str().expect("hex");
        let want = Ja4::new(&ClientHello::parse(&decode(hex)), Transport::Tcp);
        let got = Profile::from_hex(hex).expect("hex reads").ja4();
        assert_eq!(got.hashed(), want.hashed(), "{}", line["name"]);
    }
}

#[test]
fn chrome_120_to_131_adds_mlkem_and_drops_padding() {
    let report = diff("Chrome-120/sni", "Chrome-131/sni");
    assert_eq!(
        sections(&report),
        [Section::Extensions, Section::Groups, Section::KeyShare]
    );
    assert_eq!(
        changes(&report, Section::Extensions),
        [Change::Removed("padding (21)".into())]
    );
    let mlkem = [Change::Added("X25519MLKEM768 (4588)".into())];
    assert_eq!(changes(&report, Section::Groups), mlkem);
    assert_eq!(changes(&report, Section::KeyShare), mlkem);
    assert_eq!(report.ja4.parts_match, [false, true, false]);
}

#[test]
fn chrome_131_to_133_moves_alps_to_the_new_codepoint() {
    let report = diff("Chrome-131/sni", "Chrome-133/sni");
    assert_eq!(sections(&report), [Section::Extensions, Section::Alps]);
    let alps = [
        Change::Removed("application_settings_old (17513)".into()),
        Change::Added("application_settings (17613)".into()),
    ];
    assert_eq!(changes(&report, Section::Extensions), alps);
    assert_eq!(
        changes(&report, Section::Alps),
        [Change::Changed {
            from: "application_settings_old (17513)".into(),
            to: "application_settings (17613)".into(),
        }]
    );
    assert_eq!(report.ja4.parts_match, [true, true, false]);
}

#[test]
fn shuffled_extensions_are_equivalent_unless_strict() {
    let bytes = decode(&hex("Chrome-133/sni"));
    let mut hello = ClientHello::parse(&bytes);
    hello.extensions.reverse();
    let shuffled = Profile::from_bytes(&encode(&hello)).expect("re-encoded hello reads");
    let original = Profile::from_bytes(&bytes).expect("hello reads");

    let report = compare(&original, &shuffled, &Options::default());
    assert!(report.is_equivalent(), "{report}");

    let strict = Options {
        strict_order: true,
        ..Options::default()
    };
    let report = compare(&original, &shuffled, &strict);
    assert_eq!(sections(&report), [Section::Extensions]);
    assert!(matches!(
        changes(&report, Section::Extensions)[..],
        [Change::Order { .. }]
    ));
}

#[test]
fn firefox_and_chrome_differ_almost_everywhere() {
    let report = diff("Firefox-120/sni", "Chrome-133/sni");
    for section in [
        Section::Ciphers,
        Section::Extensions,
        Section::Groups,
        Section::KeyShare,
        Section::SignatureAlgorithms,
        Section::CertCompression,
        Section::RecordSizeLimit,
        Section::Alps,
    ] {
        assert!(sections(&report).contains(&section), "{section}: {report}");
    }
    assert_eq!(report.ja4.parts_match, [false, false, false]);
}

#[test]
fn ignored_sections_are_skipped() {
    let options = Options {
        ignore: [Section::Extensions, Section::Alps].into(),
        ..Options::default()
    };
    let report = compare(
        &profile(&json("Chrome-131/sni")),
        &profile(&json("Chrome-133/sni")),
        &options,
    );
    assert!(report.is_equivalent(), "{report}");
}

#[test]
fn sni_value_and_tls_record_header_do_not_matter() {
    let message = decode(&hex("Chrome-133/sni"));
    let len = u16::try_from(message.len()).expect("fits").to_be_bytes();
    let record = [&[0x16, 0x03, 0x01, len[0], len[1]][..], &message].concat();
    let from_record = Profile::from_bytes(&record).expect("record reads");

    let mut tls = json("Chrome-133/sni");
    for extension in tls["extensions"].as_array_mut().expect("extensions") {
        if extension.get("server_name").is_some() {
            extension["server_name"] = "other.example".into();
        }
    }
    let report = compare(&from_record, &profile(&tls), &Options::default());
    assert!(report.is_equivalent(), "{report}");
}

#[test]
fn http2_is_compared_when_both_have_it() {
    let with_http2 = |akamai: &str| {
        profile(&json!({
            "tls": json("Chrome-133/sni"),
            "http2": { "akamai_fingerprint": akamai },
        }))
    };
    let chrome = with_http2("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p");
    let other = with_http2("1:65536;4:6291456;2:0;6:262144;3:100|15663105|0|m,s,a,p");
    let report = compare(&chrome, &other, &Options::default());
    assert_eq!(
        sections(&report),
        [Section::Http2Settings, Section::Http2PseudoHeaders]
    );
    assert_eq!(
        changes(&report, Section::Http2Settings),
        [
            Change::Added("MAX_CONCURRENT_STREAMS (3) = 100".into()),
            Change::Order {
                from: vec!["1".into(), "2".into(), "4".into(), "6".into()],
                to: vec!["1".into(), "4".into(), "2".into(), "6".into()],
            },
        ]
    );

    let tls_only = profile(&json("Chrome-133/sni"));
    let report = compare(&chrome, &tls_only, &Options::default());
    assert!(report.is_equivalent(), "{report}");
    assert_eq!(report.notes.len(), 1);
}

#[test]
fn bad_input_is_an_error() {
    assert!(Profile::parse("").is_err());
    assert!(Profile::parse("not hex").is_err());
    assert!(Profile::parse("020000").is_err());
    assert!(Profile::parse("{\"tls\": {}}").is_err());
    assert!(Profile::parse("{").is_err());
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, text).expect("writing a test input");
    path
}

#[test]
fn cli_exit_codes() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fpdiff-cli");
    fs::create_dir_all(&dir).expect("creating the test directory");
    let c131 = write(&dir, "c131.json", &json("Chrome-131/sni").to_string());
    let c133 = write(&dir, "c133.json", &json("Chrome-133/sni").to_string());
    let c133_hex = write(&dir, "c133.hex", &hex("Chrome-133/sni"));
    let garbage = write(&dir, "garbage.txt", "zz");

    let run = |args: &[&Path]| {
        Command::new(env!("CARGO_BIN_EXE_fpdiff"))
            .args(args)
            .output()
            .expect("running fpdiff")
    };
    let same = run(&[&c133, &c133_hex]);
    assert_eq!(same.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&same.stdout).ends_with("equivalent\n"));

    let different = run(&[&c131, &c133]);
    assert_eq!(different.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&different.stdout);
    assert!(stdout.contains("[alps]"), "{stdout}");
    assert!(
        stdout.contains("  + application_settings (17613)"),
        "{stdout}"
    );

    assert_eq!(run(&[&c131, &garbage]).status.code(), Some(2));

    let json_output = Command::new(env!("CARGO_BIN_EXE_fpdiff"))
        .args([c131.as_os_str(), c133.as_os_str()])
        .args(["--json", "--ignore", "extensions"])
        .output()
        .expect("running fpdiff");
    assert_eq!(json_output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&json_output.stdout).expect("--json prints JSON");
    assert_eq!(report["equivalent"], false);
    assert_eq!(
        report["differences"]
            .as_object()
            .expect("differences")
            .keys()
            .collect::<Vec<_>>(),
        ["alps"]
    );

    let unknown = Command::new(env!("CARGO_BIN_EXE_fpdiff"))
        .args([c131.as_os_str(), c133.as_os_str()])
        .args(["--ignore", "nope"])
        .output()
        .expect("running fpdiff");
    assert_eq!(unknown.status.code(), Some(2));
}
