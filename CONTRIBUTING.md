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

`cargo build --release` produces `target/release/mirrust` and `target/release/fpdiff`.
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

The workspace lints are strict: `unsafe` code is forbidden, public items need documentation,
and Clippy's `pedantic` group and `unwrap_used` are on. `-D warnings` turns every lint warning
into an error.

## Dependencies

After a change to a dependency or to `Cargo.lock`, check the advisories, the licences and the
duplicate versions. Neither tool is installed by the repository, and CI does not run them
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
