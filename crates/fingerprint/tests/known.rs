//! The browser profiles of `corpus/hellos.jsonl` against the known clients of
//! `corpus/clients.jsonl`: each profile with SNI is in the dataset under its name.

use fingerprint::known::{self, Match};
use fingerprint::{ClientHello, Ja4, Transport};
use serde_json::Value;

const HELLOS: &str = include_str!("../../../corpus/hellos.jsonl");

/// Names (without `suffix`) and JA4 of the profiles whose name ends in `suffix`, leaving out
/// the randomized hellos.
fn profiles(suffix: &str) -> Vec<(String, Ja4)> {
    HELLOS
        .lines()
        .filter_map(|line| {
            let case: Value = serde_json::from_str(line).expect("corpus line is JSON");
            let name = case["name"].as_str().expect("corpus name");
            if name.starts_with("Randomized") {
                return None;
            }
            let profile = name.strip_suffix(suffix)?.to_owned();
            let hex = case["hex"].as_str().expect("corpus hex");
            let message: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("corpus hex is valid"))
                .collect();
            let ja4 = Ja4::new(&ClientHello::parse(&message), Transport::Tcp);
            Some((profile, ja4))
        })
        .collect()
}

/// Whether the entry's source lists `profile` as one of its comma-separated names.
fn names_profile(source: &str, profile: &str) -> bool {
    source
        .split([' ', ','])
        .any(|word| word.trim_end_matches(',') == profile)
}

#[test]
fn every_profile_with_sni_matches_its_entry_exactly() {
    let profiles = profiles("/sni");
    assert!(profiles.len() > 30, "too few profiles: {}", profiles.len());
    for (profile, ja4) in profiles {
        let Match::Exact(client) = known::lookup(&ja4) else {
            panic!("{profile} ({}) has no exact match", ja4.hashed());
        };
        assert_eq!(client.ja4_r(), ja4.raw(), "{profile}");
        assert!(
            names_profile(client.source(), &profile),
            "{profile} matched {:?}",
            client.source()
        );
    }
}

#[test]
fn a_profile_without_sni_is_a_cipher_match_with_its_own_cipher_list() {
    // Without a server name part a changes (`i`, one extension fewer), so the match is never
    // exact; the cipher list is the one of the entry that names the profile. Part c can
    // change too: Chrome-120 sends the padding extension in one hello and not in the other.
    let with_sni = profiles("/sni");
    for (profile, ja4) in profiles("/nosni") {
        let Match::Ciphers(client) = known::lookup(&ja4) else {
            panic!("{profile} ({}) is not a cipher match", ja4.hashed());
        };
        let own = with_sni
            .iter()
            .find(|(name, _)| *name == profile)
            .and_then(|(_, ja4)| known::lookup(ja4).client())
            .unwrap_or_else(|| panic!("{profile} has no entry"));
        assert_eq!(
            client.ja4().split('_').nth(1),
            own.ja4().split('_').nth(1),
            "{profile} matched {:?}",
            client.source()
        );
    }
}
