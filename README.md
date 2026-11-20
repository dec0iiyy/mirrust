<h1 align="center">mirrust</h1>

<p align="center"><b>See your client the way the network sees it.</b></p>

<p align="center">
  <a href="https://github.com/dec0iiyy/mirrust/actions/workflows/ci.yml"><img src="https://github.com/dec0iiyy/mirrust/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

<p align="center">
  <a href="https://github.com/dec0iiyy/mirrust/releases/latest">Download</a> &middot;
  <a href="docs/docker.md">Docker</a> &middot;
  <a href="docs/deploy.md">Deploy</a> &middot;
  <a href="docs/reference.md">Reference</a> &middot;
  <a href="https://github.com/dec0iiyy/mirrust/discussions">Discussions</a>
</p>

mirrust is an HTTPS server in one small binary. It reads the TLS ClientHello, the HTTP/2 frames
and the HTTP/3 handshake of every connection, computes the fingerprints that anti-bot systems
use, and scores whether those layers agree with each other and with the `User-Agent`.

```console
$ curl -sk https://localhost:8443/api/clean | jq -c .audit
{"score":100,"verdict":"consistent"}

$ curl -sk -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/160.0.0.0 Safari/537.36" \
    https://localhost:8443/api/clean | jq -c .audit
{"score":30,"verdict":"inconsistent"}
```

The second client is curl wearing a Chrome `User-Agent`. mirrust sees the curl TLS stack and the
missing browser headers behind it.

## Why mirrust

| | |
| --- | --- |
| **A verdict, not just hashes** | An `audit` score from 0 to 100 compares the `User-Agent`, the TLS stack, the HTTP/2 settings and the request headers, and says which layer gives the client away. |
| **Every layer on one port** | TLS over TCP and QUIC, HTTP/1.1, HTTP/2 and HTTP/3, all served from one address. |
| **The fingerprints people use** | JA4 per the FoxIO specification (with `_o`, `_r` and `_ro`), JA3, PeetPrint and the Akamai HTTP/2 string, in the JSON layout of tls.peet.ws, plus an HTTP/3 fingerprint of its own. |
| **Knows real clients** | A dataset of 52 clients: Chrome, Firefox, Safari, curl, Go, Python, Node.js, Java, Ruby, rustls and okhttp. |
| **Small and self-contained** | One binary of about 5 MB that idles at about 6 MB of memory. No database, no runtime to install. |
| **Made for the open internet** | A connection limit, bounded memory per client, property-tested parsers, no `unsafe` code, and an optional JSON Lines request log. |
| **Keeps nothing about you** | The installed service writes no request log and nothing per request to the journal. A visitor's IP address lives in memory while the page is built. |

It is for people who build or test HTTP clients and browser-impersonation libraries, run
anti-bot or anti-fraud defences, or need to see exactly what a client sends.

## Try it

**macOS and Linux** (Intel and ARM). One command downloads the right binary into the current
folder, checks its checksum, and needs no `sudo`:

```console
$ curl -fsSL https://github.com/dec0iiyy/mirrust/releases/latest/download/install.sh | sh -s -- --prefix .
$ ./mirrust
listening on https://127.0.0.1:8443 (TCP and HTTP/3 over UDP)
self-signed certificate: open https://localhost:8443 in a browser and accept the warning, or run: curl -k https://localhost:8443
```

**Windows** (PowerShell):

```powershell
> Invoke-WebRequest https://github.com/dec0iiyy/mirrust/releases/latest/download/mirrust-windows-x86_64.exe -OutFile mirrust.exe
> .\mirrust.exe
```

Then, in another terminal, look at it: `open https://localhost:8443` on macOS, `xdg-open
https://localhost:8443` on Linux, `start https://localhost:8443` on Windows. Or stay in the
terminal with `curl -k https://localhost:8443`. Stop the server with Ctrl-C. To install it for
good, run `curl -fsSL https://github.com/dec0iiyy/mirrust/releases/latest/download/install.sh | sh`,
which puts `mirrust` in `/usr/local/bin`. To build it yourself you need Rust 1.88 or later:
`cargo build --release`, then `./target/release/mirrust`.

Open <https://localhost:8443> in a browser for the page: the score, every check behind it, the
fingerprints, the cipher suites and extensions in the order sent, and the full JSON. The
certificate is self-signed, so use `curl -k` on the command line, where `/` prints a plain-text
report:

```console
$ curl -k https://localhost:8443
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
         or tunnel the TCP stack is the exit's, the User-Agent the device's,
         and the two disagree here

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

`/` answers with this text unless the request's `Accept` header contains `text/html` (browsers),
so curl, wget and scripts get text and browsers get the page; `?format=html` and `?format=text`
force either, `/text` is always text, and `?color=1` adds ANSI colour for a terminal (off by
default, so a pipe or a file stays clean).

## Test your own client

`mirrust probe` starts a throwaway server on 127.0.0.1, runs your command with `MIRRUST_URL` and
`MIRRUST_CACERT` set, and prints the report of each connection it made on stderr:

```console
$ mirrust probe -- sh -c 'curl -s --cacert "$MIRRUST_CACERT" "$MIRRUST_URL" >/dev/null'
$ mirrust probe --fail-under 80 -- ./run-my-client   # exit 3 if the lowest audit score is below 80
```

It runs on loopback: TCP checks come from the loopback SYN on Linux (not measured on macOS and
Windows), and a proxy or middlebox on a real network is not part of the test. Flags and exit
codes: [docs/reference.md](docs/reference.md#probe).

## Deploy

On a Linux server with systemd and a DNS `A` record for your host name pointing at it:

```console
$ curl -fsSL https://github.com/dec0iiyy/mirrust/releases/latest/download/install.sh | sh
$ sudo /usr/local/bin/mirrust install --domain mirror.example.com
```

The first command downloads the binary for the machine (Linux or macOS, x86_64 or arm64),
checks it against the release's `SHA256SUMS` and installs it as `/usr/local/bin/mirrust`. The
second copies the binary there if it is not already, writes the sandboxed systemd unit from
[`deploy/mirrust.service`](deploy/mirrust.service) with your flags, and starts the service on
TCP and UDP port 443. Run it again with other flags to change them, and `sudo mirrust
uninstall` to remove it. Open TCP and UDP port 443 in the firewall and nothing else: UDP
carries HTTP/3.

mirrust gets a Let's Encrypt certificate for that name by itself (TLS-ALPN-01 on port 443, so
no port 80) and renews it; `--domain` means you accept the Let's Encrypt Subscriber Agreement.
Add `--acme-staging` to try it out first. Without systemd, run the binary yourself:
`sudo mirrust --domain mirror.example.com`. Or in Docker:

```console
$ docker run -d --name mirrust --restart unless-stopped -p 443:443/tcp -p 443:443/udp \
    --sysctl net.ipv4.ip_unprivileged_port_start=0 -v mirrust-data:/data \
    ghcr.io/dec0iiyy/mirrust --domain mirror.example.com --acme-dir /data/acme
```

To do it by hand (download without the script, your own unit, certificate files from certbot,
log rotation), follow [docs/deploy.md](docs/deploy.md); for Docker Compose and the image,
[docs/docker.md](docs/docker.md). `deploy/cloud-init.yaml` is an untested cloud-config for a
fresh VPS. `mirrust install` and the built-in ACME client have run on an Ubuntu 24.04 server on
the internet, with the Let's Encrypt staging CA and then production (see
[docs/deploy.md](docs/deploy.md#install-with-mirrust-install)).

## Documentation

- [Reference](docs/reference.md): flags, API, JSON fields, the request log.
- [Fingerprints](docs/fingerprints.md): how every value is computed, and the `audit` checks.
- [Common clients](docs/clients.md): how curl, Python, Node, Go, `reqwest` and Chrome score, and what a faked `User-Agent` costs.
- [Architecture](docs/architecture.md): how a connection is read, limits and known gaps.
- [Contributing](CONTRIBUTING.md) and [Security](SECURITY.md).

## Status

Version 0.1.5. 368 tests, run on Ubuntu, macOS and Windows in CI. The release binaries are built
in CI for Linux (static, x86_64 and arm64), macOS and Windows, and the container image is built
and smoke-tested there on amd64 and arm64. A Linux binary has run under the sandboxed systemd
unit on an Ubuntu 24.04 server, on port 8443, and answered over HTTP/1.1, HTTP/2 and, with
Chrome, HTTP/3. Since then it has also run on port 443 of an Ubuntu 24.04 server on the
internet, installed with `mirrust install`, with a Let's Encrypt certificate it obtained itself,
and answered over HTTP/1.1 and HTTP/2. Not run yet: IPv6, log rotation, HTTP/3 against that
server and HTTP/3 in the container. On Linux the server takes each connection's TCP SYN from
the kernel for the TCP checks of the `audit`; a test on Ubuntu in CI reads a loopback SYN, and
one report from the internet showed the MSS check passing, but that is a single look. On macOS
and Windows the TCP checks show as not measured. Details are in
[Reference](docs/reference.md#status).

## License

GPL-3.0-only. The project builds on TrackMe by pagpeter (GPL-3.0); see [NOTICE](NOTICE) and
[LICENSE](LICENSE).
