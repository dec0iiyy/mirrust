# Architecture

## Crates

```
fingerprint   ClientHello parser, JA3, JA4, ja4_peet, PeetPrint, details,    (no I/O)
              known-client lookup over corpus/clients.jsonl
audit         consistency checks and score                                   (no I/O; uses fingerprint)
http2         HTTP/2 frame parser, Akamai fingerprint, one-request responder (tokio I/O traits only)
quic          QUIC Initial decryption and CRYPTO reassembly                  (rustls::quic for crypto)
http3         HTTP/3 SETTINGS, unidirectional stream types, fingerprint      (no I/O)
tcpip         TCP SYN parser, tcp_syn details, p0f signature                 (no I/O)
server        mirrust binary: listeners, TLS, HTTP/1, HTTP/2, HTTP/3, routes, request log
fpdiff        (crates/diff) fingerprint comparison, library and CLI; uses fingerprint
golden        snapshot files under corpus/ for the tests; a dev-dependency only
```

`server` depends on `fingerprint`, `audit`, `http2`, `http3`, `quic` and `tcpip`. The parsing
crates take bytes and return values; they do not open sockets, so they can be used offline on
captured data and are tested on the corpus without a network.

The workspace forbids `unsafe` code (`unsafe_code = "forbid"`) and is kept free of warnings
under `cargo clippy --workspace --all-targets -- -D warnings` (pedantic lints enabled).

## Request flow

### TCP: HTTP/1.1 and HTTP/2

Before any of the steps below, `serve` asks the shared `ConnectionLimit` (a tokio `Semaphore`
sized by `--max-connections`, 1024 by default) for a permit. Without one the accepted stream is
dropped, which closes it, and the refusal is counted. The permit moves into the connection's
task and is released when the task ends.

```
accept ──► read ClientHello records ──► ALPN acme-tls/1? ──yes──► challenge certificate, close
                    (--domain only)               │
                                                  no
                                                  ▼
                              fingerprint ──► rustls handshake (replayed bytes)
                                                              │
                                              ALPN h2 ────────┼──── otherwise
                                                ▼                       ▼
                                       http2::serve              http1::serve
                                                └──────► route ◄────────┘
                                                           │
                                                 request log, stdout line
```

0. **Take the SYN from the kernel (Linux).** `serve` sets `TCP_SAVE_SYN` on the listening
   socket, and the kernel then keeps the SYN of every connection it accepts, from the IP
   header to the end of the TCP header. `handle` reads it with `TCP_SAVED_SYN` as its first
   act (`crates/server/src/syn.rs`), and `tcpip::Syn::parse` turns it into the report's
   `tcpip.tcp_syn` and `tcpip.p0f` and into the `Syn` the `audit` judges `tcp_os` and
   `tcp_mss` on. Where the options do not exist, or the kernel has nothing, there is no SYN
   and the report says "not measured"; nothing fails. See
   [Known gaps](#known-gaps) for what this does not cover.
1. **Capture the ClientHello before rustls.** rustls does not expose the raw ClientHello, so
   the server reads TLS records off the socket itself until one whole handshake message is
   assembled (it may span several records). The first record must be a handshake record and the
   first message a ClientHello; the message is capped at 64 KiB. Every byte read is kept.
   **The challenge branch.** With `--domain`, `Config::challenges` is set, and `handle` looks at
   the ALPN list of the captured ClientHello (`AcmeChallenges::is_challenge`, which uses the
   `fingerprint` parser). If it offers `acme-tls/1`, the connection is the CA validating a name
   (TLS-ALPN-01, RFC 8737): the captured bytes go into `Rewind` as usual, but the stream is given
   to a second `TlsAcceptor` whose certificate resolver holds the challenge certificates of the
   order in progress, keyed by name, and whose only ALPN protocol is `acme-tls/1`. The
   handshake is run and the connection closed. `handle` then returns `Ok` whatever happened:
   nothing is logged, no failure is counted, no report is built. The connection holds its
   connection slot and the 15-second deadline like any other. Without `--domain`, or when ALPN
   does not offer `acme-tls/1`, the next step is unchanged.
2. **Replay into rustls.** The kept bytes are put back in front of the socket (`Rewind`) and the
   stream is handed to `tokio_rustls::TlsAcceptor`, which performs a normal handshake. The server
   offers ALPN `h2` then `http/1.1` and accepts TLS 1.2 and 1.3. If the handshake fails or runs
   into the connection's deadline, and `--log` is on, the ClientHello is fingerprinted with
   negotiated version 0 and logged with the error (`RequestLog::record_failed_handshake`); the
   connection then ends.
3. **Fingerprint.** `TlsDetails::new` parses the captured message twice: `parse` for the FoxIO
   JA4 values, `parse_peet` for everything else (see
   [fingerprints.md](fingerprints.md#1-reading-the-clienthello)), and takes the negotiated
   version from rustls for `ja4_peet` and `tls_version_negotiated`. It also looks the FoxIO
   `ja4` up in the known-client dataset. The `audit` is computed when a report is turned into
   JSON, from the raw message (parsed a third time with `parse`), the `User-Agent`, the
   dataset match, the Akamai string and the request headers.
4. **Serve by ALPN.**
   - `h2`: `crates/http2` reads the preface, sends the server SETTINGS (initial window 1048576,
     100 concurrent streams, header list 65536), and reads frames until the first `END_STREAM`
     (the parser refuses more than 64 KiB of input or more than 256 frames:
     `http2::DEFAULT_MAX_INPUT`, `http2::MAX_FRAMES`). Each SETTINGS frame and each PING is
     answered with its ACK as it arrives (RFC 9113 sections 6.5.3 and 6.7). The report is
     built, and on the last HEADERS frame's stream the server sends HEADERS, the body in DATA
     frames of at most 1024 bytes, an empty DATA with `END_STREAM`, and GOAWAY. It waits
     500 ms and closes.
     **Flow control.** The body is sent within the client's windows (RFC 9113 section 6.9):
     65,535 bytes for the connection and for the stream unless the client's SETTINGS
     (`INITIAL_WINDOW_SIZE`) and `WINDOW_UPDATE` frames say otherwise. A body that fits the
     windows set before the request ended goes out in one write; that is every answer to an
     ordinary request (a report is 7 to 9 KB, the page with it about 40 KB). Otherwise the
     server sends what fits and reads the
     client's frames until a `WINDOW_UPDATE` or a new `INITIAL_WINDOW_SIZE` opens the window,
     acknowledging SETTINGS and PING meanwhile; `RST_STREAM` on the stream or GOAWAY ends the
     response early, other frames are ignored, and this reading stops at 64 KiB of input.
     A window pushed past 2^31 - 1 stays at that value instead of being an error.
     **Errors.** When the client's frames break the protocol or pass a limit, the server sends
     `RST_STREAM` for the request (if a HEADERS frame came) and GOAWAY, both with the error
     code (RFC 9113 sections 5.4.1 and 7: `PROTOCOL_ERROR`, `FLOW_CONTROL_ERROR`,
     `FRAME_SIZE_ERROR`, `COMPRESSION_ERROR`, or `ENHANCE_YOUR_CALM` for the 64 KiB, 256-frame
     and header-size limits). The GOAWAY has the highest stream the client used as its last
     stream and the reason as debug data, such as `input exceeds the size limit`. A lower last
     stream would tell the client that its request was not looked at, and curl and Go then
     send it again on a new connection, up to five times for curl, to be refused each time
     (RFC 9113 section 6.8). The `RST_STREAM` is there because curl and the `h2` crate report
     its code to their user and not the GOAWAY's. The server then shuts down
     its sending side and reads and drops what the client still sends for up to 500 ms, because
     closing a socket with unread input resets the connection and the reset can overtake the
     GOAWAY. Bytes that are not the HTTP/2 preface get no frame (section 3.4), and neither
     does a connection that fails or times out.
   - anything else: HTTP/1.1. The request is read until its head ends (the first empty line)
     or 16 KiB are in, parsed, and answered with `Content-Length` and `Connection: close`.
     The server then shuts down its sending side and reads on for up to 500 ms, until the
     client closes: a request can be longer than what was read (a body, a head over 16 KiB),
     and closing a socket with unread input resets the connection, which can cost the client
     the response. Three things here differ from tls.peet.ws, which this code began as a copy
     of, because RFC 9112 is the better guide for a public server:
     - Nothing follows the body. tls.peet.ws writes two CRLFs past `Content-Length`.
     - A line may end with a bare LF (RFC 9112 section 2.2 allows a recipient to accept it).
       Before, only CRLF CRLF ended a head, so a client that sent bare LFs got no answer until
       the connection's 15 seconds ran out.
     - The read limit is 16 KiB, not 1024 bytes, so the head of a browser's request with its
       cookies is read whole. A head over 16 KiB is not refused with 431: the report is built
       from the part that was read, its last line cut, and the `audit` does not judge the
       headers of such a request, since some may be missing.
5. **Route and log.** The router builds the body from the report (`/` is the text report from
   `text.rs` or the HTML page, chosen by the request's `Accept` header and `?format=`; the
   header is read from the request into `Report::accept` by each of the three handlers), the request log gets an entry,
   and a one-line summary goes to stdout (written synchronously on the connection's task). The method and path in that line are the client's
   own text, so they are printed with `escape_debug` and cut at 200 characters (`…`); the
   request log is JSON and needs no such step.

The whole connection, handshake included, must finish within 15 seconds: the task fixes a
deadline when it starts and each step (reading the ClientHello, the handshake, serving the
request) runs under `timeout_at` that deadline.

A connection that fails prints nothing at once. `FailureLog` (the `failures` field of `Config`,
shared by TCP and QUIC like the connection limit) counts it by kind: not TLS (the first bytes are
not a ClientHello), timeout, EOF (the client closed or reset the connection) or other. The first
failure after a report starts a 30-second wait, after which one line on stderr gives the counts;
a quiet period prints nothing. For `other` the line also has the peer and text of the last such
error, escaped and cut at 1024 characters. The text includes the causes of the error, such as
the parser's reason when the HTTP/2 exchange was rejected.

Every response carries the headers in `routes::RESPONSE_HEADERS` (`Cache-Control: no-store`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Vary: Accept`) and, on HTTP/1.1 and HTTP/2, a `Date` header (`routes::date`; the HTTP/2 handler takes it
when the connection starts). The HTTP/1.1 and HTTP/3
handlers write the fixed ones from that list; the HTTP/2 handler passes it to `http2::serve` as
`extra_headers`, which also puts them on the `OPTIONS` answer and sends the names in lowercase.
The `OPTIONS` answer is built by the HTTP/2 handler and passed to `http2::serve` as `options`
(empty body, `text/plain; charset=utf-8`, the CORS headers, `Alt-Svc`), so it has the same
headers as the HTTP/1.1 answer; `crates/http2` calls the router's callback for every other method.

### UDP: HTTP/3

```
UDP socket ──► SniffingSocket.poll_recv ──► quinn endpoint ──► h3 ──► route
                     │                                      ▲
                     └─► per-connection quic::InitialAssembler ┘ ClientHello by (peer, original DCID)
```

HTTP/3 runs on `quinn` (with the aws-lc-rs provider), `h3` and `h3-quinn`, on the same address
and port as TCP. The TLS configuration is the TCP listener's, with ALPN `h3`. 0-RTT is not
enabled.

Each `quinn::Incoming` needs a permit from the same `ConnectionLimit` as TCP connections;
without one it is refused (`Incoming::refuse`, which answers `CONNECTION_REFUSED`). The permit
is held until the connection's task ends, at most 15 seconds later.

Neither quinn nor rustls exposes the ClientHello, so the server wraps the UDP socket quinn reads
from (`SniffingSocket`, an `AsyncUdpSocket`). Each received datagram is passed on to quinn
unchanged; datagrams with a long header are also fed to a `quic::InitialAssembler` of their
connection, found by (peer address, Destination Connection ID) (GRO batches are split by their stride first). Nothing is done on the send side. A completed
ClientHello is stored under (peer address, original Destination Connection ID). The connection
task reads both from `quinn::Incoming`, waits for the handshake to finish (by then every Initial
packet has passed through the socket), and takes the entry.

Connections that share one client address, such as several connections of one UDP socket, have
separate assemblers because their Destination Connection IDs differ. The
in-progress and finished tables are each capped at 4096 entries. Initial keys are public, so
anyone can fill a table with valid Initial packets from spoofed addresses; therefore a newcomer
always gets a slot: entries older than 5 seconds are dropped first, and if the table is still
full the oldest entry is evicted. The assembler accepts at most 16 KiB of CRYPTO data
(`quic::MAX_CRYPTO_LEN`) and keeps a buffer no longer than the contiguous prefix received plus
4 KiB, so one spoofed frame at a far offset costs a few KiB and a CRYPTO frame beyond that is an
error. Each CRYPTO frame is merged into a sorted range list with two binary searches, and a
frame that would make the 65th separate range is an error (`quic::Error::TooManyCryptoRanges`),
so the work under the sniffer's lock stays linear in the size of the datagram.

Each request on an HTTP/3 connection gets the same routes and report as HTTP/2, with
`http_version: "h3"`, `Transport::Quic` (JA4 prefix `q`) and negotiated version 772. Up to 100 requests per
connection are answered, one after another; after the 100th the server sends GOAWAY
(`h3::server::Connection::shutdown`) and rejects later requests, and the connection ends when the
client hangs up or its 15 seconds run out.

The endpoint's `quinn::TransportConfig` limits what a client can make the server hold:
16 concurrent bidirectional and 8 unidirectional streams, a 128 KiB receive window per stream
and 256 KiB per connection, and an idle timeout equal to the 15-second connection timeout.
`h3` is built with `max_field_section_size(64 KiB)`, which it also sends to the client in
SETTINGS. `h3` buffers a whole HEADERS frame, so the stream window (128 KiB) is what bounds a
request that ignores the limit. A header section over the limit is not answered: the handler treats
the error as fatal for the connection and ends it, so the client sees a closed stream or
connection and no response (`h3_does_not_answer_a_request_with_oversized_headers_and_keeps_serving`
in `crates/server/tests/h3.rs`).

The report also has a `quic` object, from the header fields and datagram sizes the assembler
kept, and an `http3` object. `h3` reads the client's control stream itself and exposes neither
its SETTINGS frame nor the stream types, so the server gives `h3` a `TapConnection` in place of
the `h3_quinn` connection: it implements the `h3::quic` traits by delegation, and the
unidirectional receive streams it hands out copy the first 1024 bytes they read into a table
shared with the request handler (at most 16 streams). `crates/http3` turns those bytes into the
object. `h3` polls the unidirectional streams before it asks for the next request stream, so
`TapConnection` holds request streams back until the SETTINGS frame has been copied, for at
most 250 ms after the handshake; the object is built once, at the first request.

This design was chosen over a UDP front end that forwards to quinn through a socket pair: there
is no second socket, no address rewriting, and quinn still sees the real peer address.

### Request log

`RequestLog::record` (a routed request) and `RequestLog::record_failed_handshake` (a TCP
connection whose handshake failed after its ClientHello was read) serialize the entry on the
connection task and `try_send` it to a bounded channel (4096 entries). A failed-handshake entry
is a request entry built from a report with no request, so its request fields are empty
strings, plus `handshake_error`. A single writer task owns the file (opened in append mode) and writes
through a buffer, flushing every 256 lines or every second. A full channel drops the entry and
increments a counter; the writer reports new drops on stderr. If a write fails, the writer
prints the error and ends; from then on every entry is counted as dropped and the server keeps
serving.

### Shutdown

On Unix `main` installs handlers for SIGINT and SIGTERM before it prints the listening line;
elsewhere it listens for Ctrl-C. It then waits for a signal or for a listener to fail. On a signal it drops both
accept loops, the log writer drains the channel and flushes, the total drop count is printed if
non-zero, and the process exits with status 0. Connection tasks still running are not waited
for; they end with the process, and what they would have logged is lost.

JSON Lines was chosen over a columnar format such as Parquet: no large dependency, each line is
readable as soon as it is flushed, a crash loses only the unflushed lines rather than the whole
file, appending across restarts needs nothing special, and `jq`, DuckDB and pandas read it
directly.

## Design decisions

- **Certificates come from a resolver, not a fixed pair.** With `--domain` the TLS
  configuration for TCP, and the one `serve_h3` turns into a QUIC configuration, use
  `acme::CurrentCert`, a `ResolvesServerCert` that returns the latest certificate (a
  `RwLock<Option<Arc<CertifiedKey>>>`), or fails the handshake while it is empty. The ACME task
  (`acme::start`) swaps a new certificate in after each order, so a renewal needs no restart
  and TCP and QUIC always agree.
- **`instant-acme`, not `rustls-acme`.** `rustls-acme` 0.15.4 brings its own async stack
  (`async-io`, `async-web-client`, `blocking`), `chrono`, `x509-parser` and a second `rcgen`
  (0.13), and its acceptor wants to read the ClientHello itself, which this server already
  does before rustls. `instant-acme` 0.8.5 (Apache-2.0) adds `hyper` and `hyper-rustls` on the
  rustls, aws-lc-rs and `rcgen` the workspace already has, and leaves the connection handling
  alone. The TLS-ALPN-01 certificate is built with `rcgen`
  (`CustomExtension::new_acme_identifier` with the SHA-256 of the key authorization, critical).
- **The rustls provider is named.** Every TLS configuration this crate builds
  (`tls_config`, `tls_config_with_resolver`, the TLS-ALPN-01 acceptor) is built with
  `builder_with_provider` on aws-lc-rs, and `main` installs aws-lc-rs as the process default
  before anything else, for the libraries that ask for the default (the ACME client's HTTPS
  connection). `ServerConfig::builder()` without an installed default works only while one
  provider feature of rustls is compiled in, and panics at first use once a dependency turns
  on a second.
- **The SYN comes from the kernel, through one small dependency.** `TCP_SAVE_SYN` and
  `TCP_SAVED_SYN` need no packet capture, no root and no `CAP_NET_RAW`, no table that pairs
  packets with connections, and have no race between capture and handler; a retransmitted
  SYN does not replace the saved one. The unit's sandbox allows them: `getsockopt` and
  `setsockopt` are in systemd's `@network-io` set, which `@system-service` includes
  (`src/shared/seccomp-util.c` in systemd, read on 2026-11-20), and `RestrictAddressFamilies=`
  concerns `socket()` only.
  Calling `getsockopt` takes `unsafe`, which this workspace forbids, and the usual wrappers
  do not have these two options (checked in socket2 0.6.5, nix 0.31.2 and rustix 1.1.6,
  none of which has a `getsockopt` for an arbitrary option either). The `tcp-save-syn` crate,
  version 0.1.0, does: 186 lines, two `unsafe` blocks (a `setsockopt` with an `i32`, and a
  `getsockopt` into a 128-byte buffer on the stack, whose returned length the kernel keeps
  within the one it was given), `libc` as its only dependency (already in the tree, one
  copy), Apache-2.0, and functions that exist and do nothing on other systems, so the server
  has no conditional code for this. All of it was read before it was added, and the archive
  that was read has the SHA-256 that `Cargo.lock` pins. It is a single release by one
  publisher, from January 2026, which is why it was read rather than trusted: read it again
  when its version changes. Its one weakness as an API is that it takes `AsRawFd`, not
  `AsFd`; the server passes it tokio's own listener and stream.
- **Capture before the TLS library.** Reading the ClientHello from the socket and replaying it
  keeps the exact bytes the client sent, independent of what rustls parses or exposes, and the
  same code works for any rustls version.
- **Two parsing modes, two JA4 values.** The FoxIO JA4 is the interoperable value and is
  reported as `ja4`. The tls.peet.ws value is kept as `ja4_peet` because fingerprints recorded
  from that service are widely used; both come from the same captured bytes.
- **Compatibility output is pinned by snapshots.** Values whose definition is "what tls.peet.ws
  reports" are specified in [fingerprints.md](fingerprints.md) and frozen in `corpus/*expected*`
  snapshots. Changing one is a deliberate act (`MIRRUST_BLESS=1 cargo test`, then review the
  diff).
- **Malformed input never panics.** The parsers return partial values; the corpus includes 700
  truncated and corrupted ClientHellos, malformed HTTP/2 streams and 262 SYN packets, some of
  them malformed.
- **Bounded memory per client.** HTTP/3 header section ≤ 64 KiB, 128 KiB per stream and 256 KiB
  per QUIC connection in flight, ClientHello ≤ 64 KiB over TCP, CRYPTO data ≤ 16 KiB per QUIC
  connection (buffer ≤ received prefix + 4 KiB), HTTP/2 input ≤ 64 KiB and ≤ 256 frames before
  the first request ends, HTTP/1 request ≤ 16 KiB, sniffing tables ≤ 4096 entries, log queue
  ≤ 4096 entries, 15 s per connection.
- **Bounded number of clients.** At most `--max-connections` connections (1024 by default) are
  open at once, TCP and QUIC together; the rest are closed or refused before any of the above is
  allocated for them. Refusals are counted and reported on stderr at most once per 10 seconds.

  What the two bounds add up to was measured with `.github/scripts/memory-under-load.py`,
  which starts a server, holds all 1024 slots with one kind of client and reads the
  server's resident memory from `ps` (release build, macOS on arm64, 2026-11-20):

  | 1024 connections that each | Resident memory |
  | --- | --- |
  | (no connection) | 9 MiB |
  | send nothing | 25 MiB |
  | send 60 KB of a ClientHello that claims 65 KB | 154 MiB |
  | finish TLS and send 16 KB of an HTTP/1.1 head that does not end | 59 MiB |
  | finish TLS and send an HTTP/2 request with 62 KB of DATA that does not end | 156 MiB |
  | finish an HTTP/2 request with 60 KB of headers and a zero window, so that the report waits | 215 MiB |
  | a quarter each of the first four | 99 MiB |

  The memory is not given back to the system when the connections close; it is used again.
  `MemoryMax=512M` in the systemd unit is the largest of these with a wide margin, because
  two things were not measured: the Linux binary, which has another allocator, and QUIC,
  where a connection may hold 256 KiB of received data by configuration, 256 MiB for 1024
  connections.
- **No caching of reports.** Every response says `Cache-Control: no-store`, because a report is
  only true for the connection it was sent on.
- **Text for terminals.** `/` answers a client that does not accept `text/html` with a plain
  ASCII report (`crates/server/src/text.rs`) instead of the page. It is rendered from the same
  `Report` and audit as the JSON, and everything the client chose in it is escaped.
- **Pages built into the binary.** The index and 404 pages are compiled in. The index page
  receives the report of the connection that loaded it, inlined as JSON; the encoder escapes
  `<`, `>` and `&`, so the report cannot close the `<script>` element it is placed in.
- **The facts about the ClientHello are computed twice, and a test holds the two together.**
  The text report's TLS block (`signals` in `crates/server/src/text.rs`) and the page's "At a
  glance" tiles (`signals` in `crates/server/static/index.html`) read the same seven facts
  from the report: the highest TLS version, post-quantum key exchange, Encrypted ClientHello,
  the server name, ALPN, legacy cipher suites and GREASE. The page does it in JavaScript
  because it also works from `/api/all` alone, and each side words its result for its own
  medium, so neither is generated from the other. The test
  `the_page_states_the_same_facts_as_the_text_report` runs the page's function in Node.js on
  every ClientHello of `corpus/hellos.jsonl` and compares each tile's colour and value with
  the text line. It needs `node` on the `PATH`: without it the test is skipped on a
  developer's machine and fails in CI, whose runners have it.
- **Response shape.** Known routes answer 200, unknown paths 404 with the built-in page, and a
  route that cannot answer 500 with `{"error": "..."}`. Real status codes let clients and
  monitoring tell the cases apart. HTTP/1 and HTTP/2 connections carry one request.

## Known gaps

- **SYN capture is for Linux and TCP only, and is proven on a loopback connection only.** The
  code was written on macOS, where the socket options do not exist; its first build and run
  was CI's on Ubuntu (`tcpip_has_the_syn_where_the_kernel_keeps_it` in
  `crates/server/tests/api.rs`), which reads the SYN of a loopback connection, checks its
  fields and the `tcp_os` check with a Linux `User-Agent`. The kernel keeps only the SYNs
  that arrive after the option is set, so `keep_syn` runs right after the port is bound.
  Until a report from a Linux server on the internet has been looked at, treat `tcpip.tcp_syn`,
  `p0f` and the `audit` checks `tcp_os` and `tcp_mss` as unproven on live traffic (middleboxes
  and NAT change TTL, MSS and options on the way). What is known to be missing or different
  from a packet capture:
  - Only the headers are kept, so `payload_len` is 0 and p0f's payload class is `0` also for a
    TCP Fast Open SYN. `tcpip.ip` and `tcpip.tcp`, which tls.peet.ws fills from the client's
    ACK, stay `{}`.
  - No SYN: on macOS and Windows; over HTTP/3, which has no TCP; for a connection accepted
    through a SYN cookie; for a connection whose SYN came before the option was set, in the
    moment between `bind` and `serve`; on a kernel before 4.2; where the sandbox refuses the
    option (gVisor); and for a SYN whose IP and TCP headers are over 128 bytes, the buffer of
    the `tcp-save-syn` crate (an IPv6 SYN with extension headers, which `tcpip` does not read
    anyway). In every one of these the report is what it was before: `tcpip` is
    `{"ip": {}, "tcp": {}}`, `tcp_os` is `skip` and `tcp_mss` is left out.
  - Behind a TCP proxy or a load balancer the SYN is the proxy's, like the ClientHello behind
    a TLS-terminating one. Docker's userland proxy, which carries connections that the host
    makes to a published port, is such a proxy; connections from outside reach the
    container through address translation and keep the client's SYN, with the container's
    address as its destination. Neither was tried.
  - If the ACK-derived fields or Fast Open payloads are ever needed, the way is an `AF_PACKET`
    socket with a BPF filter for the port, read in a blocking thread into a bounded map keyed
    by the client's address and port (first SYN wins). That needs `CAP_NET_RAW`.
- **`http3` is incomplete.** It has the client's SETTINGS, its unidirectional stream types and
  a fingerprint of both ([fingerprints.md](fingerprints.md#92-the-http3-object)). Missing parts:
  - The pseudo-header order of the request, and with it an Akamai-style last part of the
    fingerprint. `h3` hands out a decoded `http::Request`, which has no pseudo-header order. It needs the raw QPACK field section: tap the request streams as `h3_tap` taps the
    unidirectional ones (wrap `BidiStream` too), read the first HEADERS frame, and walk its
    field lines far enough to name each one. Without a dynamic table every line is a static
    table index or a literal, so no QPACK decoder state is needed, but literal names can be
    Huffman-coded.
  - Stream types that arrive after the first request is answered are not listed, and the
    fingerprint depends on which streams the client opens before its first request.
  - Frames after SETTINGS on the control stream (PRIORITY_UPDATE, GREASE frames) and the
    contents of the QPACK streams are not reported.
  - Connection flags such as 0-RTT used. (The QUIC version is in `quic`, datagram support in
    the transport parameters of `tls.extensions`.)
  - `/api/clean` and the request log do not carry the HTTP/3 fingerprint.
- **HTTP/3 transport features.** No 0-RTT and no Retry or address validation.
- **A spoofed flood still costs real clients their `tls`.** Sniffer tables evict the oldest
  entry, so a real client's ClientHello is tracked, but more than 4096 spoofed Initial packets
  inside the 5-second expiry push out entries that have not been taken yet and the affected
  clients get `"tls": null`. Telling them apart needs address validation (Retry). A ClientHello
  over 16 KiB, a CRYPTO frame more than 4 KiB ahead of the received prefix, or CRYPTO data in
  more than 64 separate pieces is not reported either, though quinn serves the connection.
- **Initial packets are decrypted under the sniffer's lock.** The table mutex is held while a
  datagram is decrypted and merged, inside `poll_recv`. Table work is logarithmic and merging is
  bounded (64 ranges), so the cost per datagram is fixed, but a high enough datagram rate still
  makes the endpoint's receive path wait on that one lock.
- **TLS 1.0 and 1.1 clients are rejected.** rustls supports only TLS 1.2 and 1.3, so a client
  that offers nothing newer fails the handshake and gets no report, although its ClientHello is
  read; with `--log`, its fingerprints are logged with `handshake_error`. The fingerprint code handles such ClientHellos (FoxIO `ja4` reads them in full;
  tls.peet.ws-compatible values are empty, see
  [fingerprints.md](fingerprints.md#1-reading-the-clienthello)).
- **One request per TCP connection.** An HTTP/1.1 request head beyond 16 KiB is truncated (the
  report sees only the first 16 KiB), a request body is not read, keep-alive is not
  supported, and HTTP/2 answers only
  the first request: requests on other streams are not read, and the GOAWAY that follows the
  response names the answered stream, so a client knows it may send them again on a new
  connection (RFC 9113 section 6.8). A request with more than 64 KiB of input before its
  `END_STREAM`, such as a POST with a large body, gets GOAWAY with `ENHANCE_YOUR_CALM` and no
  report.
- **The HTTP/2 responder is not a general server.** It does not send `WINDOW_UPDATE` (the
  64 KiB input limit is reached before the connection's receive window is), does not check
  the client's frames against the stream states of RFC 9113 section 5.1, and its HPACK encoder
  does not send a dynamic table size update when the client's `HEADER_TABLE_SIZE` is under
  4096 (RFC 7541 section 4.2); the response never refers to the dynamic table.
- **HTTP/2 header blocks split across CONTINUATION frames.** Only the HEADERS frame's own
  fragment is decoded, not the CONTINUATION frames. If the fragment ends inside a field, the
  request is refused with `COMPRESSION_ERROR`; if it ends between fields, the request is
  answered from the fields in the fragment. A client splits a header block that is larger than
  16,384 bytes after HPACK, which takes some 20 KB of cookies or other headers.
- **The HTTP/3 GOAWAY names the last answered request.** After the 100th request the server
  calls `h3::server::Connection::shutdown(0)`, which sends GOAWAY with the id of the last
  stream it accepted. RFC 9114 section 5.2 reads that id as the first request that was
  *not* processed, so formally the 100th request, which was answered in full before the frame
  went out, is declared unprocessed. A client has its response by then and has nothing to send
  again; the report it got is not affected. `shutdown(1)` would send the id after it, but h3
  0.0.8 compares incoming streams with `>` and would then also accept the 101st request, which
  the frame says is rejected. Left as it is until h3 has the comparison the RFC has.
- **What the QUIC sniffer does not report.** The sniffer reads the same datagrams as quinn, and
  three rules keep it from reporting a ClientHello that quinn did not read: a datagram under
  1200 bytes does not start an assembly, because quinn ignores one that would open a connection
  (RFC 9000 section 14.1); CRYPTO data that differs from an earlier copy of the same bytes ends
  the assembly for good (`quic::Error::CryptoConflict`), because a receiver may keep either
  copy and quinn's choice depends on offsets and sizes; and a malformed packet behind an
  Initial packet in one datagram does not cost the packets in front of it, as in quinn. In the
  second case the connection is served and its report has `"tls": null`. No honest client
  sends either.
- **QUIC limits.** Packet numbers are decoded as if nothing was acknowledged (true for a client's
  first flight); Retry and Version Negotiation packets are ignored and only the length of the
  token is reported; no draft versions. The `quic` object covers the first flight only: nothing
  from Handshake or 1-RTT packets (ACK behaviour, packet number lengths, frame order) is read.
- **IP-in-IP packets** (protocol 4 or 41) give no SYN in `tcpip`.
- **No HTTP-to-HTTPS redirect listener and no IP block list.**
- **No per-address connection limit.** `--max-connections` is one number for the whole server,
  so a single address can hold every slot, each for up to 15 seconds.
- **Running out of file descriptors.** A failed `accept` is reported on stderr and retried
  after 100 ms, so the server keeps running, but it serves nobody while the limit is hit. Keep
  the open-file limit above `--max-connections`.
- **Failed QUIC handshakes are not logged**, and connections in progress are not drained on
  shutdown.
- **The request log stops after a write error** (a full disk, a removed directory). Nothing
  reopens the file; restart the service. See [deploy.md](deploy.md#6-rotate-the-request-log).
- **The stdout line per request is a blocking write** made on the connection's task. If
  whatever reads stdout stops reading and the pipe fills, serving slows down; discard stdout
  or keep it flowing.
- **The known-client dataset is small** (31 entries: 20 from uTLS browser profiles and 11 captured), so
  many real clients get a `ciphers` or `none` match. The HTTP/2 fingerprint stored with an
  entry is used by the `audit` but not by the matching.
- **`fpdiff`** compares only the Akamai string for HTTP/2, not `sent_frames`; JA4 is recomputed
  from the compared fields, so extension 53 entries count as signature algorithms there.
