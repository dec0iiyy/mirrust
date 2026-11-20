# Reference

Flags, API, fields, the request log and the workspace. For the short version see the [README](../README.md); [fingerprints.md](fingerprints.md) specifies every value, [architecture.md](architecture.md) explains how it works and [deploy.md](deploy.md) sets it up on a server.

## What you see

- **The text report at `/`.** `curl -k https://localhost:8443` prints the score with a bar,
  every check with what it found (problems first), the fingerprints, and the facts about the
  ClientHello a person scans: TLS version, cipher and extension counts, ALPN, SNI, post-quantum
  key exchange, Encrypted ClientHello, legacy cipher suites and GREASE. It is ASCII, at most 78
  columns wide and has no raw hex; see [Text report](#text-report).
- **The page at `/`.** Open the server in a browser. The page shows the `audit` score and
  verdict, every check behind them with what it found, the fingerprints, the cipher suites and
  extensions in the order sent, the HTTP/2 frames or HTTP/1 headers, for HTTP/3 the QUIC and
  SETTINGS details, and the full JSON of the response.
- **The `audit` score.** A client that matches a known client and agrees with its
  `User-Agent` scores 100 and the verdict is `consistent`. curl with a Chrome `User-Agent`
  header scores 30 and is `inconsistent`. The score is only as good as the layers the server
  can observe and the clients in its dataset; see [Status](#status).
- **The JSON.** The same data for programs, in the layout of tls.peet.ws. `/api/clean` is
  the short form; this is `curl -k https://localhost:8443/api/clean` with the long values
  shortened to `...`:

```json
{
  "ja3": "771,4867-4866-...",
  "ja3_hash": "375c6162a492dfbf2795909110ce8424",
  "ja4": "t13d4907h2_0d8feac7bc37_7395dae3b2f3",
  "ja4_r": "t13d4907h2_0004,0005,...",
  "ja4_peet": "t13d497h2_0d8feac7bc37_7395dae3b2f3",
  "ja4_peet_r": "t13d497h2_0004,0005,...",
  "akamai": "3:100;4:10485760;2:0|1048510465|0|m,s,a,p",
  "akamai_hash": "64a832f547be33249bf4d33e8a46c5dc",
  "peetprint": "772-771-770-769|2-1.1|...",
  "peetprint_hash": "0d6ceceb9e71ec096d2022ad0651e2f2",
  "http_version": "h2",
  "client": {
    "match": "exact",
    "family": "curl",
    "version": "8.7.1",
    "library": "LibreSSL 3.3.6",
    "source": "captured locally, curl 8.7.1 (LibreSSL/3.3.6, nghttp2/1.69.0), macOS 27.2.1 system curl, HTTP/2",
    "user_agent_family": "curl",
    "consistent": true
  },
  "audit": {
    "score": 100,
    "verdict": "consistent"
  }
}
```

## What it reports

- the parsed ClientHello: cipher suites, every extension with its decoded contents, client
  random, session id, and the raw message;
- JA4 as defined by the FoxIO specification (`ja4`, `ja4_r`, `ja4_o`, `ja4_ro`), over TCP and QUIC;
- JA3 and its MD5;
- PeetPrint and its MD5;
- the JA4 variant that tls.peet.ws reports, kept under `ja4_peet` / `ja4_peet_r`;
- for HTTP/2, every frame the client sent before its request ended and the Akamai HTTP/2
  fingerprint;
- for HTTP/3, the ClientHello read from the client's QUIC Initial packets, the Initial's header
  fields, and the client's SETTINGS and unidirectional stream types with a fingerprint of them;
- for HTTP/1, the request's header lines in order;
- which known client the JA4 belongs to (Chrome, Firefox, Safari, curl, Go, Python, Node.js,
  okhttp, rustls, 360 Browser) and whether the `User-Agent` claims the same one;
- the `audit`: the checks that compare these layers, each with a status and the values it
  compared.

The workspace also contains a TCP SYN parser that produces the `tcp_syn` details and a p0f v3
signature. The server does not capture SYN packets yet; see
[docs/architecture.md](architecture.md#known-gaps).

The JSON layout follows tls.peet.ws, so tools written against that service can read
mirrust's output. See [Compatibility with tls.peet.ws](#compatibility-with-tlspeetws).

## Who it is for

- Anti-bot and anti-fraud teams that need to see what a client's TLS and HTTP/2 stack sends,
  and to compare it with what its `User-Agent` claims.
- Authors of HTTP clients and browser-impersonation libraries who need to check that their
  fingerprint matches a real browser's. The `fpdiff` tool in this workspace compares two
  fingerprints field by field.
- Developers of censorship-resistance and privacy tools who need to know which TLS and HTTP
  features make their traffic distinguishable.
- Security analysts who hunt by JA4 and want to see which value a given client produces, with
  the raw parts (`ja4_r`, `ja4_ro`) for comparison.

## Status

This is version 0.1.0.

Measured today: the TLS ClientHello over TCP and QUIC, the HTTP/1 request headers, the HTTP/2
frames and Akamai fingerprint, the first flight of a QUIC connection, and the HTTP/3 SETTINGS
and unidirectional stream types. The `audit` uses only these.

Not measured yet:

- **TCP SYN.** The parser in `crates/tcpip` is tested on recorded packets, but the server does
  not capture SYN packets. `tcpip` is always `{"ip": {}, "tcp": {}}`, the `audit` check
  `tcp_os` has the status `skip` ("Not measured"), and `tcp_mss` does not appear.
- **The HTTP/3 request's pseudo-header order**, so the HTTP/3 fingerprint covers SETTINGS and
  stream types only. It is not in `/api/clean` or in the request log.

Tested: `cargo test --workspace` (247 tests), clippy, `cargo fmt --all --check` and the build
with Rust 1.88 in CI on Ubuntu and macOS, and on macOS `cargo doc --workspace --no-deps` and
release binaries queried with curl and Chrome.

Run on a server: on Ubuntu 24.04 (x86_64, systemd 255), the release binary built in CI
on Ubuntu 24.04 ran under the sandboxed unit of `deploy/mirrust.service`, adapted to
port 8443 and a self-signed certificate. It answered over HTTP/1.1, HTTP/2 (curl) and HTTP/3
(Chrome), served 300 requests at 20 in parallel without an error, peaked at about 3.5 MB of
memory, and stopped cleanly. See [deploy.md](deploy.md) for the details.

Not run yet: port 443, IPv6, the firewall steps, the logrotate rules and the Docker image in
`deploy/`. Also not run: the built-in ACME client (`--domain`) against Let's Encrypt, staging
or production. Its flags, the validation connection, the certificate resolver, the cache and
the retry timing are tested; the exchange with the CA, which the `instant-acme` library
performs, is not, and nor is the current `deploy/mirrust.service` with `StateDirectory=` on a
server. Treat those instructions as written but unverified.

The dataset behind the `client` field has 31 entries, so a real client often gets `ciphers`
or `none`; see [docs/fingerprints.md](fingerprints.md#12-known-clients-client).

## Command line

```
mirrust [--listen ADDR] [--cert PEM --key PEM | --domain NAME ...]
        [--acme-dir DIR] [--acme-email ADDR] [--acme-staging]
        [--cors-key KEY] [--log PATH] [--max-connections N]
mirrust --version
mirrust install (--domain NAME ... | --cert PEM --key PEM) [--acme-email ADDR] [--acme-staging]
        [--log PATH] [--max-connections N] [--dry-run]
mirrust uninstall [--dry-run]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen ADDR` | `127.0.0.1:8443`; `0.0.0.0:443` with `--domain` | Socket address to bind. TCP serves HTTP/1.1 and HTTP/2; UDP on the same address serves HTTP/3. |
| `--cert PEM` | none | PEM certificate chain. Must be given together with `--key`. Conflicts with `--domain`. |
| `--key PEM` | none | PEM private key. Without `--cert`/`--key` and without `--domain`, a self-signed certificate for `localhost` and `127.0.0.1` is generated. |
| `--domain NAME` | none | Get a Let's Encrypt certificate for this host name and renew it ([ACME](#built-in-acme)). Repeat for up to 4 names on one certificate. `auto` means `A-B-C-D.sslip.io` for the machine's public IPv4 address `A.B.C.D`. Conflicts with `--cert`/`--key`. Accepts the Let's Encrypt Subscriber Agreement. |
| `--acme-dir DIR` | `./mirrust-acme` | Where the ACME account key and the issued certificate are kept, so a restart does not order again. Needs `--domain`. |
| `--acme-email ADDR` | none | Contact address given to Let's Encrypt when the account is created. Needs `--domain`. |
| `--acme-staging` | off | Use the Let's Encrypt staging CA, whose certificates browsers do not trust. Takes no value. Needs `--domain`. |
| `--cors-key KEY` | `X-CORS` | A request with a header line that starts with this text gets CORS headers. An empty value turns this off. |
| `--log PATH` | no log | Append one JSON line per request, and per TLS handshake that fails after the ClientHello, to this file. See [Request log](#request-log). |
| `--max-connections N` | `1024` | Connections that may be open at the same time, TCP and QUIC counted together; at least 1. See [Connection limit and shutdown](#connection-limit-and-shutdown). |
| `-h`, `--help` | | Print usage and exit. |
| `-V`, `--version` | | Print `mirrust X.Y.Z` (the version of the `server` package) and exit with status 0. Like `--help`, it wins over the other flags. |

Each flag but `--acme-staging` takes its value as the next argument (`--listen 0.0.0.0:443`,
not `--listen=...`).

### `install` and `uninstall`

`mirrust install` sets mirrust up as a systemd service and `mirrust uninstall` removes it. Both
work on Linux with systemd only, as root, and refuse otherwise; `--dry-run` works as any user on
any system. The first argument must be `install` or `uninstall`, and each takes its own flags
(the serving flags of the server are not accepted after them, except those below).
[deploy.md](deploy.md#install-with-mirrust-install) describes what they do, step by step.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--domain NAME` | none | Let's Encrypt certificate for this name, as for the server. Repeat for up to 4, or `auto` alone. Conflicts with `--cert`/`--key`. Accepts the Let's Encrypt Subscriber Agreement. |
| `--cert PEM`, `--key PEM` | none | Certificate chain and key, as absolute paths, given together. The unit loads them with `LoadCredential=`, so a renewed certificate needs a restart. |
| `--acme-email ADDR` | none | As for the server. Needs `--domain`. |
| `--acme-staging` | off | As for the server. Takes no value. Needs `--domain`. |
| `--log PATH` | `/var/log/mirrust/requests.jsonl` | Request log. Must be a file inside `/var/log/mirrust`. |
| `--max-connections N` | mirrust's own default, `1024` | As for the server; at least 1. |
| `--dry-run` | off | Print each step and, for `install`, the unit text; change nothing. Takes no value. |
| `-h`, `--help` | | Print the usage of `install` and `uninstall`. |

One of `--domain` and `--cert`/`--key` is required. Not accepted: `--listen` (the unit always
has `0.0.0.0:443`), `--acme-dir` (the unit passes the service's state directory,
`/var/lib/mirrust`) and `--cors-key`; use the manual unit in [deploy.md](deploy.md) for those.

`install` copies the running executable to `/usr/local/bin/mirrust` (mode 0755, replaced
atomically, skipped when it already is that file), writes `/etc/systemd/system/mirrust.service`
from `deploy/mirrust.service` with the `ExecStart=` block replaced, runs `systemctl
daemon-reload`, `systemctl enable mirrust.service` and `systemctl restart mirrust.service`, and
waits up to 5 seconds for `systemctl is-active` to say `active`. Run again with other flags, it
rewrites the unit and restarts the service. It exits with an error if the service is not
active at the end. `uninstall` runs `systemctl disable --now mirrust.service` (a failure is
reported and ignored), removes the unit and `/usr/local/bin/mirrust`, and runs `systemctl
daemon-reload`; it keeps `/var/lib/mirrust` and `/var/log/mirrust`.

The live path of both has not been run on a machine with systemd; see
[deploy.md](deploy.md#what-was-tested).

### Built-in ACME

`--domain` makes mirrust obtain and renew its own certificate from Let's Encrypt with the
TLS-ALPN-01 challenge (RFC 8737) on the TCP listener, so only port 443 is needed. TCP port 443
is where Let's Encrypt validates: with `--listen` on another port mirrust starts but prints a
warning.

- The server starts serving at once. Until the first certificate exists a TLS handshake fails
  (TCP and QUIC); the certificate is then replaced while the server runs, at the start of each
  handshake, so a renewal needs no restart.
- It prints the notice about the Subscriber Agreement once, and then one `acme:` line on
  stderr per event: obtaining or using the cached certificate, ordering, issued or renewed with
  the days of validity left, and failed with the CA's error text and the wait before the next
  attempt. After a failure it waits 5 minutes, then twice as long each time up to 6 hours. A
  certificate is renewed 30 days before it ends, or a third of its lifetime before it ends if
  that is shorter.
- A connection whose ClientHello offers ALPN `acme-tls/1` is the CA validating a name. It gets
  the challenge certificate, takes a connection slot like any connection, and is not written to
  the request log and not counted in the failure summary.
- `--acme-dir` and every directory it creates have mode 0700 on Unix, and the files in it
  (`account.json`, `private-key.pem`, `certificate.pem`, `names.txt`, in a subdirectory
  `letsencrypt` or `letsencrypt-staging`) mode 0600. Key material is never printed.
- `--domain auto` finds the local address of the default route without sending a packet, and
  refuses to start if it is loopback, private (RFC 1918), link-local, in `100.64.0.0/10` or
  otherwise not routable. sslip.io is a free third-party DNS service.

See [deploy.md](deploy.md#3-point-the-name-at-the-server-and-get-a-certificate) for the setup
and for what is tested and what is not.

The `--cors-key` prefix is compared with the start of each header line (`Name: value`) without
regard to ASCII case, so the default `X-CORS` matches `x-cors-…` headers on HTTP/2 and HTTP/3 as
well. On HTTP/3 only the header names are compared, so a key that contains `: ` never matches
there. `OPTIONS` requests always get an empty `text/plain` answer with the CORS headers.

Each routed request also prints one line on stdout: `IP METHOD HTTP_VERSION PATH JA3_HASH`.
`OPTIONS` requests, failed handshakes and failed connections print no such line. `JA3_HASH` is
`-` when no ClientHello was captured, and the method and path are escaped and cut at 200
characters.

### Connection limit and shutdown

While `--max-connections` connections are open, a new TCP connection is closed as soon as it is
accepted, before anything is read from it, and a new QUIC connection is refused with
`CONNECTION_REFUSED`. A slot is free again when its connection ends, which is at most 15
seconds after it was accepted. The limit is for the whole server; there is no limit per client
address.

Refusals do not print a line each. They are counted, and the count is printed on stderr 10
seconds after the first refusal not yet reported, so at most one line every 10 seconds:

```
37 connections refused: the limit of 1024 simultaneous connections was reached
```

Connections that fail (a client that is not speaking TLS, a timeout, a client that hangs up,
any other error) are counted by kind in the same way. The count is printed on stderr 30
seconds after the first failure not yet reported:

```
4 connections failed in 30 s: 2 not TLS, 2 eof
```

An `other` failure adds `; last other: PEER: TEXT` with the last such error.

Ctrl-C (SIGINT) and, on Unix, SIGTERM stop the server: it stops accepting connections, writes
what is queued for the request log, flushes the file and exits with status 0. Connections still
open at that moment are cut off, not finished.

## API

| Route | Response |
| --- | --- |
| `/` | The text report or the HTML page, by `Accept` and `?format=`; see [Text report](#text-report). |
| `/text` | The text report, whatever the request asks for. |
| `/api/all` | The full report as indented JSON. |
| `/api/tls` | The report with only the `tls` object filled in: `ip`, `http_version` and `method` are empty strings, and there is no `user_agent`, `client` or `audit`. |
| `/api/clean` | The fingerprints, the `client` object and the `audit` score and verdict. |
| `/api/raw` | The ClientHello as hex and base64: `{"raw": "...", "raw_b64": "..."}`. |
| anything else | A 404 page built into the binary. |

The query string and fragment are ignored for routing, and percent-encoded paths are decoded.
Known routes answer with status 200 and unknown paths with 404. A route that cannot answer
returns status 500 with `{"error": "..."}` (for example `/api/raw` when no ClientHello was
captured). Every body is UTF-8 and its `Content-Type` says `charset=utf-8`.

Every response carries these headers, on HTTP/1.1, HTTP/2 and HTTP/3, for every route and
status and for `OPTIONS` answers:

| Header | Value | Why |
| --- | --- | --- |
| `Cache-Control` | `no-store` | A report describes the connection it was sent on; a stored copy would describe another one. |
| `X-Content-Type-Options` | `nosniff` | The body is to be read as its `Content-Type` says. |
| `Referrer-Policy` | `no-referrer` | Links on the page do not tell other sites where the visitor came from. |
| `Vary` | `Accept` | `/` answers with the text report or the page by `Accept`, so a cache must not serve one for the other. It is on every response, because HTTP/2 sends these headers from one fixed list. |

HTTP/1.1 and HTTP/2 connections are closed after one response. An HTTP/3 connection answers up
to 100 requests, one after another; then the server sends GOAWAY.

### `/api/all`

```json
{
  "ip": "127.0.0.1:52144",
  "http_version": "h2",
  "method": "GET",
  "user_agent": "curl/8.7.1",
  "tls": { "...": "..." },
  "http2": { "...": "..." },
  "tcpip": { "ip": {}, "tcp": {} },
  "client": {
    "match": "exact",
    "family": "curl",
    "version": "8.7.1",
    "library": "LibreSSL 3.3.6",
    "source": "captured locally, curl 8.7.1 (LibreSSL/3.3.6, nghttp2/1.69.0), macOS 27.2.1 system curl, HTTP/2",
    "user_agent_family": "curl",
    "consistent": true
  },
  "audit": {
    "score": 100,
    "verdict": "consistent",
    "checks": [ { "id": "tls_known", "status": "pass", "...": "..." } ]
  }
}
```

The keys come in this order: `ip`, `http_version`, `method`, `user_agent`, `tls`, then
`http1` or `http2`, or `quic` and `http3`, then `tcpip`, `client` and `audit`.

| Field | Content |
| --- | --- |
| `ip` | Client address with port. |
| `http_version` | `h2`, `h3`, or the HTTP/1 request line's version (`HTTP/1.1`). `--` when the HTTP/1 request line is not three space-separated parts. |
| `method` | Request method. |
| `user_agent` | `User-Agent` value; left out when empty. |
| `tls` | TLS details, below. `null` for an HTTP/3 request whose ClientHello was not captured. |
| `http1` | HTTP/1 only: `{"headers": [...]}`, every header line as sent, in order. |
| `http2` | HTTP/2 only: `akamai_fingerprint`, `akamai_fingerprint_hash`, `sent_frames`. |
| `quic` | HTTP/3 only: `version`, `dcid_length`, `scid_length`, `token_length`, `initial_datagrams`, `initial_datagram_sizes`, read from the client's Initial packets. Absent when they were not captured. |
| `http3` | HTTP/3 only: `fingerprint`, `fingerprint_hash`, `settings` (the client's SETTINGS as `{id, name, value}` in wire order) and `streams` (the unidirectional streams it opened as `{id, type, name}`), as of the connection's first request. |
| `tcpip` | Always `{"ip": {}, "tcp": {}}` until SYN capture is added. |
| `client` | The known client the TLS fingerprint matches, and whether the `User-Agent` agrees; below. |
| `audit` | A consistency score from 0 to 100, a verdict (`consistent`, `suspicious` or `inconsistent`), and the checks behind it: `User-Agent` against the TLS stack, TLS against HTTP/2, request headers, and more. `null` when `tls` is `null`. See [docs/fingerprints.md](fingerprints.md#audit). |

`tls` contains:

| Field | Content |
| --- | --- |
| `ciphers` | Cipher suite names in the client's order; unnamed ones as `0x00FF`, GREASE as `TLS_GREASE (0x0A0A)`. |
| `extensions` | One object per extension in the client's order, with a `name` such as `supported_groups (10)` and decoded fields. Over QUIC, `quic_transport_parameters (57)` has `parameters`: `{id, name, value}` per transport parameter in the client's order. |
| `tls_version_record` | ClientHello `legacy_version` as a decimal string (`"771"` for 0x0303). |
| `tls_version_negotiated` | The negotiated version as a decimal string (`"772"` for TLS 1.3; always `"772"` over QUIC). |
| `ja3`, `ja3_hash` | JA3 string and its MD5. |
| `ja4`, `ja4_r` | JA4 and JA4_r per the FoxIO specification. |
| `ja4_o`, `ja4_ro` | JA4_o and JA4_ro: the same with ciphers and extensions in the client's order. |
| `ja4_peet`, `ja4_peet_r` | The JA4 variant tls.peet.ws reports under `ja4` / `ja4_r`. |
| `peetprint`, `peetprint_hash` | PeetPrint string and its MD5. |
| `client_random`, `session_id` | Hex. |

`client` contains:

| Field | Content |
| --- | --- |
| `match` | `exact`: the `ja4` equals a known client's. `ciphers`: only its cipher list does. `none`: neither. |
| `family`, `version`, `library`, `source` | The matched entry of `corpus/clients.jsonl`: client label, observed version or range, TLS library, and where the sample came from. `null` without a match. |
| `user_agent_family` | What the `User-Agent` claims: `Chrome`, `Edge`, `Firefox`, `Safari`, `curl`, `Go`, `Python`, `Node`, `okhttp` or `unknown`. |
| `consistent` | Whether the two agree, for an `exact` match with a recognized `User-Agent`; otherwise `null`. An Edge `User-Agent` is consistent with a Chrome match, since Chromium-based browsers share Chrome's TLS stack. |

A match means "identical to a client in the dataset", not proof of identity: a client can send
another's ClientHello. JA4 ignores cipher and extension order by design, so order plays no part.
Versions are not compared. The rules, the dataset format and how to add a client are in
[docs/fingerprints.md](fingerprints.md#12-known-clients-client).

`http2.sent_frames` lists each client frame with `frame_type`, `stream_id`, `length`, and the
fields that apply to it: `headers`, `settings`, `increment`, `flags`, `priority`, `payload`
(base64), `goaway`. Zero and empty fields are left out.

How every value is computed, including edge cases, is specified in
[docs/fingerprints.md](fingerprints.md).

### `/api/clean`

`ja3`, `ja3_hash`, `ja4`, `ja4_r`, `ja4_peet`, `ja4_peet_r`, `akamai`, `akamai_hash`,
`peetprint`, `peetprint_hash`, `http_version`, the `client` object described above, and
`audit` reduced to `{"score": ..., "verdict": ...}`. `akamai` and `akamai_hash` are `-` when
the request did not use HTTP/2. For an HTTP/3 request whose ClientHello was not captured, the
fingerprints are empty strings, `client.match` is `none` and `audit` is `null`.

### Text report

`/` chooses between the text report (`Content-Type: text/plain; charset=utf-8`) and the HTML page
(`text/html; charset=utf-8`) in this order:

1. `?format=html` gives the page and `?format=text` the text report; the value is compared
   without regard to ASCII case. The first `format=` in the query counts, and any other value is
   ignored.
2. Otherwise the page goes to a request whose `Accept` header contains `text/html` (any case; the
   values of several `Accept` lines are joined), which is what every browser sends.
3. Every other request, including one with no `Accept` header or with `Accept: */*` (curl, wget,
   HTTPie, scripts), gets the text report.

`/text` is the text report for every request. `/api/*` is JSON whatever the `Accept` header
says, and an unknown path gets the HTML 404 page. `?color=1` (on `/` or `/text`) wraps the text in
ANSI colour: bold titles and score, green for `ok` and a consistent verdict, yellow for `WARN`
and suspicious, red for `FAIL` and inconsistent, dim for rules, `skip` and hints. Colour is off by
default; with it, `| less -R` shows it. The `Accept` header is read the same way on HTTP/1.1,
HTTP/2 and HTTP/3.

This is what `curl -k https://localhost:8443` printed from a release binary (HTTP/2; the port in
the first line is the client's):

```
mirrust  (h2, TLS 1.3, 127.0.0.1:54902)

AUDIT  100/100  [####################]  consistent
  Looks like curl 8.7.1 (exact match). The User-Agent claims curl.

  3 checks passed, 1 not measured
  [ ok ] TLS fingerprint against known clients
         Identical to curl 8.7.1
  [ ok ] User-Agent against the TLS stack
         The User-Agent says curl, the TLS stack is curl
  [ ok ] HTTP/2 fingerprint against the client
         Settings, window and header order are those of curl
  [skip] TCP stack against the User-Agent
         Not measured: this server did not capture the TCP SYN. Behind a proxy
         or VPN the TCP stack is the exit's, the User-Agent the device's, and
         the two disagree here

FINGERPRINTS -----------------------------------------------------------------
  ja4        t13d4907h2_0d8feac7bc37_7395dae3b2f3
  ja4_o      t13d4907h2_2677ac475d6b_c6f9150fbe3b
  ja3        375c6162a492dfbf2795909110ce8424
  peetprint  0d6ceceb9e71ec096d2022ad0651e2f2
  akamai     64a832f547be33249bf4d33e8a46c5dc
             3:100;4:10485760;2:0|1048510465|0|m,s,a,p

TLS --------------------------------------------------------------------------
  Highest TLS version offered  TLS 1.3 (also 1.2, 1.1, 1.0)
  Cipher suites                49
  Extensions                   7
  ALPN                         h2, http/1.1
  Server name (SNI)            localhost
  Post-quantum key exchange    No (groups: X25519, P-256, P-384, P-521)
  Encrypted ClientHello        Not sent
  Legacy cipher suites         32 of 49 (8 broken)
  GREASE                       No

colour: ?color=1  JSON: /api/all  short JSON: /api/clean  page: /?format=html
```

The same request over `--http1.1` starts with `mirrust  (HTTP/1.1, TLS 1.3, ...)`, has no `akamai`
row and no HTTP/2 check. Over HTTP/3 the `akamai` row is an `http3` row with the hash and string
of the HTTP/3 fingerprint. With a Chrome `User-Agent` on the same curl, the checks that fail come
first:

```
mirrust  (h2, TLS 1.3, 127.0.0.1:54906)

AUDIT  30/100  [######              ]  inconsistent
  Looks like curl 8.7.1 (exact match). The User-Agent claims Chrome.

  2 failed, 2 passed, 1 not measured
  [FAIL] User-Agent against the TLS stack
         The User-Agent says Chrome, but the TLS stack is curl 8.7.1
  [FAIL] Request headers of the claimed browser
         Chrome sends these with every request; missing here: sec-ch-ua,
         sec-fetch-*, accept-language, accept-encoding
  [ ok ] TLS fingerprint against known clients
         Identical to curl 8.7.1
...
```

Layout rules: each check is a badge (`[ ok ]`, `[WARN]`, `[FAIL]`, `[skip]`), its title and
its detail indented under the title; long text wraps at the 78th column with a hanging indent
and is never cut, except a single word longer than a line. The bar has 20 cells. Everything the
client chose (the SNI, the ALPN protocols, the peer address) is cut at 200 characters, and every
control or non-ASCII character in the text is written as an escape such as `\n` or `\u{1b}`,
so a client cannot send escape sequences to its own terminal or pipe. The JA3 text and raw hex
(key shares, the ClientHello) are not printed; `/api/all` has them. Without a captured
ClientHello the report is the title line and a note saying so.

## Request log

`--log PATH` appends one compact JSON object per line (JSON Lines) for every routed request,
including 404s and error answers, and for every TLS handshake over TCP that fails after the
ClientHello was read (see [Failed handshakes](#failed-handshakes)). `OPTIONS` requests are not
routed and not logged. The file is created if needed and appended to across restarts.

| Field | When |
| --- | --- |
| `time` | Always. RFC 3339 in UTC with milliseconds, `2026-11-19T12:34:56.789Z`. |
| `ip` | Always, with port. |
| `http_version`, `method`, `path`, `user_agent` | Always; `path` is the request target as sent, query string included; `user_agent` may be `""`. |
| `ja3_hash`, `ja4`, `ja4_r`, `ja4_peet`, `peetprint_hash` | When TLS details exist. `ja4` and `ja4_r` are the FoxIO values. |
| `akamai_fingerprint`, `akamai_fingerprint_hash` | HTTP/2 requests. |
| `handshake_error` | Failed handshakes only, as the last key. |

Not logged: client random, session id, key shares, the raw ClientHello, and request headers
other than `User-Agent`. The client address is always logged; there is no switch to omit it.

### Failed handshakes

A TCP client that sent a whole ClientHello and then did not complete the TLS handshake gets one
line as well: a TLS 1.0-only client (rustls accepts only TLS 1.2 and 1.3), a scanner that sends
a ClientHello and hangs up, a client that stalls until the 15-second connection timeout.

The line has the keys of a request line, in the same order, so a reader of request lines reads
it without changes:

- `time` and `ip` as usual;
- `http_version`, `method`, `path` and `user_agent` are present and `""`, since there was no
  request;
- `ja3_hash`, `ja4`, `ja4_r`, `ja4_peet`, `peetprint_hash` are computed from the ClientHello.
  `ja4_peet` has `0` where the TLS version goes (it starts with `t0`), because tls.peet.ws puts
  the negotiated version there and none was negotiated;
- `handshake_error` comes last and holds the error text, for example
  `peer is incompatible: Tls12NotOffered` (a TLS 1.0-only client), `tls handshake eof` (the
  client hung up) or `connection timed out`.

Request lines never have `handshake_error`, which tells the two kinds apart:

```console
$ jq -c 'select(.handshake_error == null)' requests.jsonl   # requests
$ jq -c 'select(.handshake_error != null)' requests.jsonl   # failed handshakes
```

Not logged: connections that end before a whole ClientHello arrived, connections refused by
`--max-connections`, failed QUIC handshakes, and connections that completed the handshake but
sent no request that was routed.

### Delivery

Connection tasks never wait for the disk. Entries go through a queue of 4096; when it is full,
new entries are dropped and counted, and the count is printed on stderr. The writer flushes
every 256 lines or every second, whichever comes first, and when Ctrl-C or SIGTERM stops the
server. A line is readable as soon as it is flushed, and a crash loses at most the unflushed
lines. The file loads directly into `jq`, DuckDB or pandas.

If a write to the file fails, the writer prints the error on stderr and logging stops for good;
the server keeps serving, and the entries it can no longer queue are counted as dropped.

## Workspace

| Crate | Path | Contents |
| --- | --- | --- |
| `fingerprint` | `crates/fingerprint` | ClientHello parser, JA3, JA4 (FoxIO), the tls.peet.ws JA4 variant, PeetPrint, readable cipher and extension details, and the known-client lookup over `corpus/clients.jsonl`. |
| `audit` | `crates/audit` | The consistency checks and the score: whether the layers of a connection agree with the client it claims to be. Uses `fingerprint`; no I/O. |
| `http2` | `crates/http2` | HTTP/2 frame capture, Akamai fingerprint, and the one-request HTTP/2 responder. |
| `quic` | `crates/quic` | Extracts the ClientHello from a client's QUIC v1/v2 Initial packets, without a QUIC stack. |
| `http3` | `crates/http3` | HTTP/3 SETTINGS and unidirectional stream types from the first bytes of each stream, and their fingerprint. Parsing only. |
| `tcpip` | `crates/tcpip` | Parses a captured TCP SYN (from the IP header on) into `tcp_syn` details and a p0f v3 signature. Parsing only. |
| `server` | `crates/server` | The `mirrust` binary: TLS, HTTP/1.1, HTTP/2, HTTP/3, routes, request log. |
| `fpdiff` | `crates/diff` | The `fpdiff` binary and library: semantic diff of two TLS (and HTTP/2) fingerprints. |
| `golden` | `crates/golden` | Test support: the snapshot files under `corpus/` and the bless mode. Not used by the server. |

`fpdiff REFERENCE CANDIDATE` reads tls.peet.ws-style JSON (`/api/all`, `/api/tls`, or a bare
`tls` object) or a ClientHello in hex (handshake message or TLS record); `-` reads stdin. It
ignores GREASE, random values, key share bytes, padding length, the SNI value and, unless
`--strict-order` is given, extension order. Exit status: 0 equivalent, 1 different, 2 bad
input. `--json` prints a machine-readable report; `--ignore SECTION,...` skips sections
(`http2` skips all HTTP/2 sections).

```console
$ cargo run --release --bin fpdiff -- chrome.json mine.json
```

Request flow, design decisions and known gaps are in
[docs/architecture.md](architecture.md).

## Testing

```console
$ cargo test
$ cargo clippy --workspace --all-targets -- -D warnings
```

The fingerprint, HTTP/2 and SYN code is tested against golden snapshots in `corpus/`:

| Input | Snapshot | Contents |
| --- | --- | --- |
| `hellos.jsonl` | `expected.jsonl` | 121 ClientHellos from common browser and library profiles (Chrome, Firefox, Safari, iOS, Edge, OkHttp, 360, QQ, randomized), with and without SNI. |
| `malformed.jsonl` | `malformed_expected.jsonl` | 700 inputs: 697 truncated and corrupted ClientHellos derived from five of the above (Chrome 120 and 133, Firefox 120, iOS 12.1, Safari 16.0) and 3 hand-built ones. |
| `h2.jsonl` | `h2_expected.jsonl` | 34 HTTP/2 client byte streams: curl, Go `net/http` and Node `http2` sessions, and hand-built frame sequences. |
| `syn.jsonl` | `syn_expected.jsonl` | 262 IPv4 and IPv6 SYN packets: OS option sets, p0f quirks, malformed headers and options, truncations. |

Each test computes the output for every input and compares it with the snapshot. When a change
to the output is intended, regenerate the snapshots and review the diff:

```console
$ MIRRUST_BLESS=1 cargo test
$ git diff corpus/
```

`corpus/clients.jsonl` is not a snapshot but the known-client dataset behind the `client` field:
31 entries, 20 from the browser profiles of `hellos.jsonl` and 11 captured from clients through
the server. Tests check that it parses, that its JA4s are unique and are the hashes of their
`ja4_r`, and that every profile of `hellos.jsonl` with SNI is in it.

Other tests cover the JA4 worked example from the FoxIO specification, the RFC 9001 Appendix A
QUIC Initial, a recorded Chrome QUIC Initial split over two datagrams, and the server end to end
over HTTP/1.1, HTTP/2 and HTTP/3 with an in-process client, including the connection limit,
the request log and the shutdown on SIGTERM. In all, `cargo test --workspace` runs 247 tests.

## Compatibility with tls.peet.ws

The JSON field names, nesting, value formats and the tls.peet.ws-specific fingerprints
(`ja3`, `peetprint`, `ja4_peet`, the extension details, the HTTP/2 frame list and Akamai string)
are written to match what tls.peet.ws returns for the same ClientHello and HTTP/2 frames,
including its irregularities. The aim is that existing clients, dashboards and stored data that
use tls.peet.ws output can read mirrust's output, and that fingerprints taken from either can
be compared directly. The snapshots in `corpus/` pin what this code outputs; the repository has
no automated comparison with the live service, so a difference may remain.

Where tls.peet.ws departs from a published specification, mirrust keeps the tls.peet.ws value
under its usual name and adds the specified one:

- `ja4` / `ja4_r` follow the FoxIO JA4 specification. The value tls.peet.ws calls `ja4` /
  `ja4_r` is reported as `ja4_peet` / `ja4_peet_r`.
- `ja4_o` / `ja4_ro` are added.
- `client` and `audit` are added at the end of `/api/all` and `/api/clean`; `/api/tls` has
  neither. `/api/clean` carries only the `audit` score and verdict.
- `quic` and `http3` are added to HTTP/3 reports.
- Unknown paths answer 404 and a route that cannot answer gives 500, with `{"error": "..."}`.
- `tcpip` is present but empty until SYN capture is wired.

The exact differences between `ja4` and `ja4_peet`, and every preserved irregularity in the
extension details and the HTTP/2 fingerprint, are listed in
[docs/fingerprints.md](fingerprints.md).
