## What changes and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo test --workspace --locked` pass (see CONTRIBUTING.md).
- [ ] A change in behaviour has a test, and the snapshots under `corpus/` were refreshed with `MIRRUST_BLESS=1 cargo test` only if the new output is intended.
- [ ] Documentation that describes the changed behaviour is updated, and every statement in it was checked against the code.
