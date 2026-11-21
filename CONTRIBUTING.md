# Contributing to mirrust

## Build

mirrust is a Cargo workspace (`crates/*`). It needs Rust 1.88 or later and a C compiler,
which the `aws-lc-sys` dependency uses. The macOS build needed no CMake; `aws-lc-sys` can ask
for it on a platform where it has no pregenerated bindings. CI builds on Ubuntu and macOS.

```console
$ cargo build
$ cargo run --bin mirrust
listening on https://127.0.0.1:8443 (TCP and HTTP/3 over UDP)
```

`cargo build --release` produces `target/release/mirrust` and `target/release/fpdiff` (and
the dev tool `target/release/corpus-sync`, which no release ships).
[docs/reference.md](docs/reference.md) describes the command line and the API; [docs/architecture.md](docs/architecture.md)
describes the request flow and the design decisions, and
[docs/fingerprints.md](docs/fingerprints.md) specifies every reported value.

## The three checks

The CI workflow (`.github/workflows/ci.yml`) runs these on every push and pull request, on
Ubuntu and macOS, and builds with Rust 1.88, the declared minimum. Run them before you send a
change:

```console
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets --locked -- -D warnings
$ cargo test --workspace --locked
```

The workflow runs the tests on Linux and macOS, and also runs `cargo check --workspace
--all-targets --locked` with Rust 1.88, the minimum supported version (`rust-version` in
`Cargo.toml`), so the tests and examples have to build with it too. That command passed on
macOS with Rust 1.88.0 on 2026-11-20 (`rustup toolchain install 1.88.0 --profile minimal`,
then `cargo +1.88.0 check ...`). Do not use language or library features newer than that.

One test of the `server` crate runs the page's JavaScript in Node.js to compare it with the
text report (see "The facts about the ClientHello are computed twice" in
[docs/architecture.md](docs/architecture.md)). Without `node` on the `PATH` it is skipped and
says so; CI has it and does not skip.

The workspace lints are strict: `unsafe` code is forbidden, public items need documentation,
and Clippy's `pedantic` group and `unwrap_used` are on. `-D warnings` turns every lint warning
into an error.

## Dependencies

After a change to a dependency or to `Cargo.lock`, check the advisories, the licences and the
duplicate versions. Neither tool is installed by the repository; CI runs `cargo deny check` (workflow
`Dependencies`, on a dependency change and weekly) but not `cargo audit`
(`cargo install --locked cargo-deny cargo-audit`):

```console
$ cargo deny check      # reads deny.toml: advisories, licences, bans, sources
$ cargo audit           # the RustSec advisories for Cargo.lock
```

`cargo deny check` fetches the RustSec database and fails on a known advisory, a yanked
or unmaintained crate, a licence outside the permissive list in `deny.toml`, and a git or
non-crates.io source; two versions of one crate are only a warning. Regenerate
`THIRD-PARTY-LICENSES.md` too when `Cargo.lock` changes (see [docs/releasing.md](docs/releasing.md)).

## Golden snapshots

The fingerprint, HTTP/2 and SYN code is tested against the files in `corpus/`. Each input file
has a snapshot that holds, line for line, what the code reported for each case:

| Input | Snapshot | Test |
| --- | --- | --- |
| `hellos.jsonl` | `expected.jsonl` | `crates/fingerprint/tests/parity.rs` |
| `malformed.jsonl` | `malformed_expected.jsonl` | `crates/fingerprint/tests/malformed.rs` |
| `h2.jsonl` | `h2_expected.jsonl` | `crates/http2/tests/parity.rs` |
| `syn.jsonl` | `syn_expected.jsonl` | `crates/tcpip/tests/parity.rs` |

The tests call `golden::check` (`crates/golden`), which compares the fresh output with the
snapshot and, on a mismatch, fails with the line numbers and the JSON keys that differ.

When a change to the output is intended, rewrite the snapshots and review the result:

```console
$ MIRRUST_BLESS=1 cargo test
$ git diff corpus/
```

With `MIRRUST_BLESS` set to exactly `1`, `golden::check` writes the fresh output to the
snapshot file instead of comparing. A run that changes nothing rewrites every snapshot byte for
byte, so `git diff corpus/` shows only real changes. Commit the snapshot changes together with
the code that causes them, and say in the commit message why the output changed. Many values
are defined as "what tls.peet.ws reports" (see [docs/fingerprints.md](docs/fingerprints.md)),
so a snapshot diff you did not expect is usually a bug.

New test inputs go into the input file as one more line; bless once to add their snapshot
lines.

## Fuzzing

`fuzz/` holds cargo-fuzz (libFuzzer) targets for the code that reads raw client bytes. It is
its own workspace with its own `Cargo.lock`, outside `crates/*`, so `cargo test`, `cargo deny`
and the release build do not see it. Each target checks that nothing panics and that the
output keeps its documented shape and limits:

| Target | Input | Code |
| --- | --- | --- |
| `client_hello` | a handshake message | `ClientHello::parse` and `parse_peet`, JA4, JA3, PeetPrint, the details |
| `http2_frames` | a chunk size byte, then a client stream | `http2::Parser` fed whole and in chunks, HPACK, `Http2Request` |
| `quic_datagrams` | `u16`-length-prefixed datagrams | `quic::InitialAssembler`: packet headers, keys, decryption |
| `quic_crypto` | a version byte, then `u16`-length-prefixed plaintext payloads | the same, with each payload sealed into an Initial packet: frames and CRYPTO reassembly |
| `tcp_syn` | a packet from the IP header on | `tcpip::Syn::parse` |

It needs a nightly toolchain and `cargo install --locked cargo-fuzz`. From the repository root:

```console
$ cargo +nightly fuzz run client_hello -- -max_total_time=60
```

The seeds in `fuzz/corpus/<target>/*.bin` come from `corpus/*.jsonl` and the QUIC test data;
`python3 fuzz/seeds.py` writes them again. libFuzzer adds its own finds to the same directory;
`fuzz/.gitignore` keeps them out of git. The workflow `.github/workflows/fuzz.yml` runs every
target for 60 seconds weekly and on demand.

A crash is written to `fuzz/artifacts/<target>/`. Reproduce it with
`cargo +nightly fuzz run <target> <file>`, shrink it with `cargo +nightly fuzz tmin <target> <file>`,
fix the library crate, and add the shrunk input as a unit test in that crate. Do not commit the
artifact.

## Keeping the dataset fresh

`crates/fingerprint/data/clients.jsonl` (docs/fingerprints.md section 12.3) ages with every browser release.
The workflow `.github/workflows/corpus-sync.yml` runs on Mondays and on demand: it clones
curl-impersonate (MIT) shallowly, runs `crates/corpus-sync`, appends the lines it prints,
runs `cargo test -p mirrust-fingerprint` and pushes the result to the branch `corpus-sync` with one
pull request that lists the new entries and the reviewer checklist. With no new entries it
changes nothing. `corpus-sync` is a dev-only crate: the release builds only `--bin mirrust`
and it is not in `THIRD-PARTY-LICENSES.md`.

The tool reads `tests/signatures/*.yaml`, skips `partial: true` and signatures it cannot read,
rebuilds a ClientHello from each and hashes it with the `fingerprint` crate, and the HTTP/2
frames with the `http2` crate. It prints only lines whose `ja4` the file lacks, one per JA4,
and never changes existing lines; signatures whose JA4 is already there go to stderr as
widening candidates. By hand:

```console
$ git clone --depth 1 https://github.com/lexiforest/curl-impersonate.git /tmp/curl-impersonate
$ cargo run -p corpus-sync -- /tmp/curl-impersonate crates/fingerprint/data/clients.jsonl >> crates/fingerprint/data/clients.jsonl
$ cargo test -p mirrust-fingerprint
```

The reviewer checks that a new `family` has a row in `Client::agrees_with` and is in the
test's `FAMILIES` list (the test fails until it is), updates the entry counts in README.md,
docs/reference.md and docs/architecture.md, checks the version ranges (and widens existing
ones from the candidates if wanted), and decides whether resumed hellos (`pre_shared_key`)
belong in the file. The pull request needs the repository setting "Allow GitHub Actions to
create and approve pull requests"; without it the job pushes the branch and fails, and the
pull request can be opened by hand. A pull request opened with `GITHUB_TOKEN` does not start
the CI workflow; push a commit to the branch or close and reopen it.

uTLS profiles missing from `corpus/hellos.jsonl` are not synced yet; they are added by hand.

## Commits

Look at `git log` for examples. The conventions:

- A change to one crate or area starts with its name, a colon, and a lower-case summary:
  `server: --log PATH writes a JSON Lines request log`,
  `golden: fix the escaping test's expected string`. Names in use: `server`, `fingerprint`,
  `http2`, `quic`, `audit`, `golden`, `page` (the HTML pages).
- A change across the workspace is a plain sentence that starts with a capital letter:
  `Prepare for publication: publish=false on every crate, SECURITY.md, dependabot`.
- The subject says what changed, in the imperative or as a statement of the new behaviour, with
  no full stop at the end. Most subjects are under 90 characters.
- A body is optional. When there is one, it is separated by a blank line and explains what the
  subject cannot: the reason, and anything a reader of the diff would not see.
- No issue-tracker prefixes, no tags such as `feat:` or `fix:`, no trailers.

## License

mirrust is licensed under GPL-3.0-only (see [LICENSE](LICENSE) and [NOTICE](NOTICE)).
Contributions are accepted under the same license.
