<h1 align="center">mirrust</h1>

<p align="center"><b>See your client the way the network sees it.</b></p>

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
| **Knows real clients** | A dataset of 30 clients: Chrome, Firefox, Safari, curl, Go, Python, Node.js, rustls and okhttp. |
| **Small and self-contained** | One binary of about 5 MB that idles at about 6 MB of memory. No database, no runtime to install. |
| **Made for the open internet** | A connection limit, bounded memory per client, property-tested parsers, no `unsafe` code, and a JSON Lines request log. |

It is for people who build or test HTTP clients and browser-impersonation libraries, run
anti-bot or anti-fraud defences, or need to see exactly what a client sends.

## Run it

Needs Rust 1.88 or later.

```console
$ cargo build --release
$ ./target/release/mirrust
listening on https://127.0.0.1:8443 (TCP and HTTP/3 over UDP)
```

Open <https://localhost:8443> in a browser for the page: the score, every check behind it, the
fingerprints, the cipher suites and extensions in the order sent, and the full JSON. The
certificate is self-signed, so use `curl -k` on the command line.

## Deploy

On a Linux server with a host name pointing at it, three steps:

```console
$ cargo build --release && sudo install target/release/mirrust /usr/local/bin/
$ sudo certbot certonly --standalone -d mirror.example.com
$ sudo mkdir -p /var/log/mirrust && sudo mirrust --listen 0.0.0.0:443 \
    --cert /etc/letsencrypt/live/mirror.example.com/fullchain.pem \
    --key  /etc/letsencrypt/live/mirror.example.com/privkey.pem \
    --log  /var/log/mirrust/requests.jsonl
```

Open TCP and UDP port 443: UDP carries HTTP/3. For a sandboxed systemd service, certificate
renewal, log rotation and Docker, follow [docs/deploy.md](docs/deploy.md).

## Documentation

- [Reference](docs/reference.md): flags, API, JSON fields, the request log.
- [Fingerprints](docs/fingerprints.md): how every value is computed, and the `audit` checks.
- [Architecture](docs/architecture.md): how a connection is read, limits and known gaps.
- [Contributing](CONTRIBUTING.md) and [Security](SECURITY.md).

## Status

Version 0.1.0, tested on macOS: 194 tests, clippy and a release binary queried over HTTP/1.1 and
HTTP/2. The Linux build, the systemd unit and the Docker image are written but not yet run on a
server, and the server does not capture TCP SYN packets yet, so the TCP checks show as not
measured. Details are in [Reference](docs/reference.md#status).

## License

GPL-3.0-only. The project builds on TrackMe by pagpeter (GPL-3.0); see [NOTICE](NOTICE) and
[LICENSE](LICENSE).
