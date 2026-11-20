# Security policy

mirrust reads untrusted network input (TLS, HTTP/1.1, HTTP/2, HTTP/3 and QUIC packets) from
anyone who connects to it, so reports about crashes, hangs, unbounded memory use and log
injection are welcome.

## Reporting a vulnerability

Use GitHub's private reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. Please do not open a public issue for something that can take a
server down.

Include the input that triggers the problem (a hex dump of the bytes, or a short script), the
version or commit, and what you saw. A failing property test or a snapshot under `corpus/` is
the most useful reproduction.

## Supported versions

Only the latest commit on the default branch is supported while the project is at 0.x.

## Scope

In scope: the `mirrust` binary and the library crates in this repository.

Out of scope: findings that need the server's own certificate key or its host, the
self-signed development certificate being untrusted, and the fingerprints themselves being
spoofable (that is what the `audit` field is about, and it says so).
