<h1 align="center">mirrust</h1>

<p align="center"><b>See your client the way the network sees it.</b></p>

<p align="center">
  <a href="https://github.com/dec0iiyy/mirrust/actions/workflows/ci.yml"><img src="https://github.com/dec0iiyy/mirrust/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/dec0iiyy/mirrust/releases/latest"><img src="https://img.shields.io/github/v/release/dec0iiyy/mirrust" alt="Release"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> &middot;
  <a href="#test-your-own-client">Test a client</a> &middot;
  <a href="#deploy">Deploy</a> &middot;
  <a href="#options">Options</a> &middot;
  <a href="docs/reference.md">Reference</a> &middot;
  <a href="https://github.com/dec0iiyy/mirrust/discussions">Discussions</a>
</p>

mirrust is an HTTPS server in one binary. It reads the TLS ClientHello, the HTTP/2 frames and the
HTTP/3 handshake of every connection, computes the fingerprints anti-bot systems use (JA4, JA3,
PeetPrint, Akamai), and scores whether the layers agree with each other and with the
`User-Agent`. When they do not, it shows what to change.

```console
$ mirrust probe -- sh -c 'curl -s -o /dev/null -A "Mozilla/5.0 ... Chrome/160.0.0.0 Safari/537.36" \
    --cacert "$MIRRUST_CACERT" "$MIRRUST_URL"'
AUDIT  30/100  [######              ]  inconsistent
  Looks like curl 8.7.1 (same cipher suites). The User-Agent claims Chrome.
  [FAIL] User-Agent against the TLS stack
         The User-Agent says Chrome, but the TLS stack is curl 8.7.1
  [FAIL] Request headers of the claimed browser
         Chrome sends these with every request; missing here: sec-ch-ua,
         sec-fetch-*, accept-language, accept-encoding

DIFF -------------------------------------------------------------------------
  Reference           Chrome 155-160 (Canary 160.0.8171.0); captured from the
                      browser
  Extensions missing  status_request (5), signed_certificate_timestamp (18),
                      extended_master_secret (23), compress_certificate (27),
                      session_ticket (35), and 5 more
  HTTP/2 yours        3:100;4:10485760;2:0|1048510465|0|m,s,a,p
  HTTP/2 reference    1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  Headers missing     sec-ch-ua, sec-fetch-*, accept-language, accept-encoding
```

curl wearing a Chrome `User-Agent`: the `User-Agent` is one layer of four, and the other three
still say curl. The diff is against a named, recorded sample of the browser, not a spec.

## Quick start

**macOS and Linux** (Intel and ARM): one command, the right binary, checksum verified, no `sudo`.

```console
$ curl -fsSL https://github.com/dec0iiyy/mirrust/releases/latest/download/install.sh | sh -s -- --prefix .
$ ./mirrust
```

**Windows** (PowerShell):

```powershell
> Invoke-WebRequest https://github.com/dec0iiyy/mirrust/releases/latest/download/mirrust-windows-x86_64.exe -OutFile mirrust.exe
> .\mirrust.exe
```

**Docker:** [docs/docker.md](docs/docker.md). **From source:** Rust 1.88 or later,
`cargo build --release`.

It listens on `https://localhost:8443` with a self-signed certificate. Open it in a browser and
accept the warning for the page, or stay in the terminal:

```console
$ curl -k https://localhost:8443
```

`/` answers with plain text unless the `Accept` header contains `text/html`, so curl and scripts
get text and browsers get the page.

| URL | Gives |
| --- | --- |
| `/` | text report or page, by `Accept`; `?format=html`, `?format=text`, `?color=1` for ANSI colour |
| `/api/all` | everything as JSON: fingerprints, extensions, HTTP/2 frames, `audit` |
| `/api/clean` | the short JSON |

To keep it: `curl -fsSL https://github.com/dec0iiyy/mirrust/releases/latest/download/install.sh | sh`
puts `mirrust` in `/usr/local/bin`.

## Test your own client

`mirrust probe` starts a throwaway server on 127.0.0.1, runs your command with `MIRRUST_URL` and
`MIRRUST_CACERT` set, and prints each connection it saw on stderr. Your command's stdout stays
clean.

```console
$ mirrust probe -- python3 my_scraper_check.py
$ mirrust probe --fail-under 90 -- ./run-my-client     # exit 3 if the lowest score is below 90
$ mirrust probe --json -- ./run-my-client              # one JSON object per connection
```

Use it as a test in CI: a library update that changes your TLS fingerprint turns the build red.
It runs on loopback, so a proxy or middlebox on a real network is not part of the test.
Exit codes and flags: [docs/reference.md](docs/reference.md#probe).

## Deploy

On a Linux server with systemd:

```console
$ curl -fsSL https://github.com/dec0iiyy/mirrust/releases/latest/download/install.sh | sh
$ sudo mirrust install --domain mirror.example.com
```

The second command writes a sandboxed systemd unit, starts it on TCP and UDP port 443, and
mirrust gets and renews a Let's Encrypt certificate by itself (TLS-ALPN-01 on 443, no port 80).
Open TCP and UDP 443 in the firewall, nothing else. `--domain` accepts the Let's Encrypt
Subscriber Agreement.

- **No domain yet:** `--domain auto` uses `A-B-C-D.sslip.io` for the machine's public IPv4
  address (a free third-party DNS service).
- **Try first:** add `--acme-staging`.
- **Your own certificate:** `--cert PEM --key PEM` instead of `--domain`.
- **Change or remove:** run `install` again with other flags; `sudo mirrust uninstall`.
- **Privacy:** the installed service writes no request log and nothing per request to the
  journal. A visitor's IP address lives in memory while the report is built. `--log PATH` turns a
  JSON Lines log on.
- **Docker:** `docker run -d --name mirrust --restart unless-stopped -p 443:443/tcp -p 443:443/udp
  --sysctl net.ipv4.ip_unprivileged_port_start=0 -v mirrust-data:/data
  ghcr.io/dec0iiyy/mirrust --domain mirror.example.com --acme-dir /data/acme`

By hand, with certbot files or log rotation: [docs/deploy.md](docs/deploy.md).

## Options

| Flag | Default | Does |
| --- | --- | --- |
| `--listen ADDR` | `127.0.0.1:8443`, `0.0.0.0:443` with `--domain` | address, TCP and UDP (HTTP/3) |
| `--domain NAME` | | Let's Encrypt certificate for up to 4 names, or `auto` |
| `--cert PEM --key PEM` | self-signed for `localhost` | your own certificate |
| `--acme-dir DIR` | `./mirrust-acme` | where the ACME account and certificates are kept |
| `--acme-email`, `--acme-staging` | | contact address; test CA |
| `--log PATH` | no log | one JSON line per request and per failed handshake |
| `--max-connections N` | `1024` | open connections, TCP and QUIC together |
| `--cors-key KEY` | `X-CORS` | header prefix that turns on CORS; empty turns it off |

`mirrust --help`, `mirrust install --help` and `mirrust probe --help` list the rest.

## What it knows

- **Fingerprints:** JA4 per the FoxIO specification (`_o`, `_r`, `_ro` too), JA3, PeetPrint, the
  Akamai HTTP/2 string in the JSON layout of tls.peet.ws, and an HTTP/3 fingerprint of its own.
- **Layers:** TLS over TCP and QUIC, HTTP/1.1, HTTP/2 and HTTP/3 on one port; on Linux also the
  TCP SYN, for the TCP checks.
- **Known clients:** 52 recorded: Chrome, Firefox, Safari, curl, Go, Python, Node.js, Java, Ruby,
  rustls and okhttp. A weekly job proposes new ones as a pull request.
- **Small:** one 6 to 8 MB binary, no database, no runtime to install; about 10 MB resident when
  idle (measured on macOS).
- **Careful on the open internet:** connection limit, bounded memory per client,
  property-tested parsers, no `unsafe` code.

## Documentation

[Reference](docs/reference.md): flags, API, JSON fields. [Fingerprints](docs/fingerprints.md):
how each value is computed, the `audit` checks and the diff. [Common clients](docs/clients.md):
how curl, Python, Node, Go, `reqwest` and Chrome score. [Architecture](docs/architecture.md):
how a connection is read, limits and known gaps. [Deploy](docs/deploy.md),
[Docker](docs/docker.md), [Contributing](CONTRIBUTING.md), [Security](SECURITY.md).

## Status

Version 0.1.6, 388 tests, run on Ubuntu, macOS and Windows in CI. Release binaries are built in
CI for Linux (static, x86_64 and arm64), macOS and Windows, and the image for amd64 and arm64.

Run on a server on the internet (Ubuntu 24.04, port 443, installed with `mirrust install`,
Let's Encrypt certificate it obtained itself): HTTP/1.1 and HTTP/2. Checked in CI: the TCP SYN on
loopback and between two network namespaces with distinct addresses. **Not run yet:** IPv6, log
rotation, HTTP/3 against a server on the internet and in the container. The TCP checks are one
kernel (the CI runner's) and one live report; middleboxes, NAT and tunnel or proxy hops change
TTL, MSS and options. On macOS and Windows the TCP checks show as not measured. Details:
[docs/reference.md](docs/reference.md#status).

## License

GPL-3.0-only. The project builds on TrackMe by pagpeter (GPL-3.0); see [NOTICE](NOTICE) and
[LICENSE](LICENSE).
