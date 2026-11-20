# Deploying mirrust

This page sets up mirrust on a Debian or Ubuntu server (x86_64, systemd) as a sandboxed
service on TCP and UDP port 443, with a certificate from Let's Encrypt that mirrust obtains and
renews by itself. `mirror.example.com` stands for your host name throughout. To use certbot or
other certificate files instead, see [Alternative: certificate files](#alternative-certificate-files).

What has been run, on an Ubuntu 24.04 server (x86_64, systemd 255): the release binary
built in CI on Ubuntu 24.04, under a copy of the unit as it was before the built-in ACME
client existed (the certificate-file variant below), listening on port 8443 with a
self-signed certificate passed through `LoadCredential=`. `systemd-analyze verify` reported
nothing for that unit and `systemd-analyze security` rated it 1.6, "OK". The service ran as a
dynamic user, kept its request log in `/var/log/mirrust/`, answered over HTTP/1.1 and HTTP/2
(curl) and HTTP/3 (Chrome), handled 300 requests with 20 at a time without an error or a
restart (peak memory about 3.5 MB), logged failed connections, and stopped cleanly on
`systemctl stop`.

What has not been run: the built-in ACME client against Let's Encrypt, staging or production
(see [What the tests cover](#what-the-tests-cover-and-what-they-do-not)), the current
`mirrust.service` with `StateDirectory=` on a real server, port 443 (so
`CAP_NET_BIND_SERVICE` was not exercised), IPv6, the firewall steps, the logrotate rules and
the Docker image. Check those before you rely on them. `mirrust install` has the same
status: see [its section](#install-with-mirrust-install) for what was tested.

You need:

- A server with a public address and a DNS `A` record for the host name that points to it
  (or `--domain auto`, which needs no record; see step 3).
- systemd 247 or later: Debian 11, Ubuntu 22.04, or newer. Check with `systemctl --version`.
- Port 443 free for both TCP and UDP. mirrust terminates TLS itself. Do not put a
  TLS-terminating reverse proxy or CDN in front of it: mirrust would then report the proxy's
  TLS and HTTP/2 fingerprint, not the client's. A proxy would also receive the Let's
  Encrypt validation instead of mirrust.
- The `ca-certificates` package, which a normal Debian or Ubuntu server has: mirrust checks
  Let's Encrypt's own certificate against the system's root certificates.

Files used below are in [`deploy/`](../deploy): `mirrust.service`, `mirrust.logrotate`,
`Dockerfile` and `cloud-init.yaml`. The numbered steps are the manual route;
[`mirrust install`](#install-with-mirrust-install) does the same in one command. To set up a
fresh VPS at first boot, see `deploy/cloud-init.yaml` (untested, with a placeholder host name).

## Install with `mirrust install`

This is the short path on a Debian or Ubuntu server with systemd. It does what steps 1, 3 and 4
below do by hand, except the firewall (step 2), which it does not touch. With the DNS record in
place:

```console
$ curl -fsSL https://github.com/dec0iiyy/mirrust/releases/latest/download/install.sh | sh
$ sudo mirrust install --domain mirror.example.com
```

`install.sh` is a release file of the first release after 0.1.0, and is in the repository's
root before that. It detects the system with `uname`, downloads the binary and `SHA256SUMS`
with curl (or wget) into a temporary directory, checks the SHA-256 before it installs
anything, runs `gh attestation verify` as well when `gh` is installed (and only reports the
result), and installs `/usr/local/bin/mirrust` with mode 0755. If that directory is not
writable it uses `sudo` for the install step only, and without `sudo` it installs into
`$HOME/.local/bin` and tells you to add that to `PATH`. Options: `--version vX.Y.Z` (default:
the latest release) and `--prefix DIR`; `install.sh --help` lists them. It works on Linux and
macOS, x86_64 and arm64; on Windows or anything else it prints where the releases are and exits
with an error. The checksum file comes from the same place as the binary, so the check catches
a damaged download; the attestation is what shows the file was built by this repository's
release workflow.

Or fetch the binary yourself (step 1) and run `sudo ./mirrust install --domain ...` from where
it is: the command copies itself.

### What it does

`mirrust install` works on Linux with systemd only, as root. It refuses, with a message, on
another operating system, when `/run/systemd/system` does not exist (systemd is not the running
init system) and when it is not run as root. Then, in this order:

1. Copies the running executable to `/usr/local/bin/mirrust` with mode 0755: it writes a
   temporary file next to it and renames it over the target, so the file is never half
   written. When the running executable already is that file, it does nothing.
2. Writes `/etc/systemd/system/mirrust.service` (mode 0644, the same way). The text is
   [`deploy/mirrust.service`](../deploy/mirrust.service), built into the binary, with its
   `ExecStart=` block replaced by one for your flags, `LoadCredential=` lines added when you
   give `--cert` and `--key`, and a comment on top saying who wrote the file. Everything else in
   the unit, the sandbox included, is the template's.
3. Runs `systemctl daemon-reload`, `systemctl enable mirrust.service` and `systemctl restart
   mirrust.service`. The restart starts a stopped service and restarts a running one, which is
   what makes running the command again apply new flags.
4. Waits up to 5 seconds for `systemctl is-active mirrust.service` to say `active`, prints the
   state, `journalctl -u mirrust -f` for the log, and the ports to open (TCP 443 and UDP 443).
   If the service is not active by then, it says so and exits with an error; the reason is in
   `systemctl status mirrust.service` and the journal.

It makes no network connection itself; the certificate order starts when the service does.
With `--domain` it prints the notice that this means accepting the Let's Encrypt Subscriber
Agreement. It does not open the firewall: do that as in [step 2](#2-open-the-firewall).

### Flags

| Flag | Meaning |
| --- | --- |
| `--domain NAME` | Get and renew a Let's Encrypt certificate for this name (up to 4, or `auto`). Written as `--domain NAME` and `--acme-dir ${STATE_DIRECTORY}` in the unit. |
| `--cert PEM`, `--key PEM` | Use these files instead, as in [Alternative: certificate files](#alternative-certificate-files): absolute paths, given together, copied for the service by `LoadCredential=` at each start. They conflict with `--domain`. One of the two kinds is required. |
| `--acme-email ADDR` | Contact address for Let's Encrypt. Needs `--domain`. |
| `--acme-staging` | Use the staging CA. Needs `--domain`. |
| `--log PATH` | Request log. Default `/var/log/mirrust/requests.jsonl`. It must be a file inside `/var/log/mirrust`, the only place the unit's sandbox lets the service write. |
| `--max-connections N` | Written as `--max-connections N`; without it mirrust's default (1024) applies. |
| `--dry-run` | Print every step and the unit text, change nothing. Works as any user on any system. |

Flag combinations that make no sense are refused before anything is touched: `--cert` without
`--key` or the other way round, `--domain` with `--cert`, `--acme-email` or `--acme-staging`
without `--domain`, neither `--domain` nor `--cert`, a `--log` outside `/var/log/mirrust`, and a
value with white space, quotes, `$`, `%`, `;` or a backslash, which a unit would read
differently. The unit always has `--listen 0.0.0.0:443`; for IPv6, another port or other
changes, use the manual unit below (the sections on the listening address and the output).

### Change the flags, uninstall

Run `mirrust install` again with the flags you want. It rewrites the unit and restarts the
service; flags you leave out go back to their defaults, because the unit is written from
scratch. Do not edit `/etc/systemd/system/mirrust.service` by hand if you mean to run the
command again: it overwrites the file.

```console
$ sudo mirrust uninstall
```

stops and disables the service, removes the unit and `/usr/local/bin/mirrust`, and runs
`systemctl daemon-reload`. It keeps the ACME account key and certificates in `/var/lib/mirrust`
and the request log in `/var/log/mirrust` (with the unit's dynamic user the real directories
are `/var/lib/private/mirrust` and `/var/log/private/mirrust`) and tells you so; delete them
yourself if you do not need them. `--dry-run` works for it as well.

### Dry run

```console
$ mirrust install --dry-run --domain mirror.example.com
dry run: nothing is changed. A real run needs root on Linux with systemd running.
1. copy /path/to/mirrust to /usr/local/bin/mirrust, mode 0755, replacing it atomically (skipped when it is already that file)
2. write /etc/systemd/system/mirrust.service, mode 0644, replacing it atomically
3. run: systemctl daemon-reload
4. run: systemctl enable mirrust.service
5. run: systemctl restart mirrust.service

/etc/systemd/system/mirrust.service would contain:
...
```

The dry run prints the unit text in full. Check it before the real run if you want to see
exactly what will be written. It does not check the system (a dry run on a Mac works), and with
`--cert` it does not check that the files exist; a real run does.

### What was tested

The functions that decide what is written (the unit derived from the template, the flag checks,
the host checks, the plan) are unit-tested, and `--dry-run`, the flag errors and `--help` are
tested by running the binary. **The live path has not been run:** the file writes under `/etc`
and `/usr/local/bin`, the `systemctl` calls, the wait and the messages after them have never
run on a machine with systemd, because they were written on a Mac. Run it first on a server you
can rebuild, with `--acme-staging`, and read the journal.

## 1. Get the binary

### Build on the server

The distribution's Rust packages may be older than the required Rust 1.88, so install Rust with
rustup. A C compiler is needed for the `aws-lc-sys` crate.

```console
$ sudo apt update
$ sudo apt install build-essential curl ca-certificates git
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ . "$HOME/.cargo/env"
```

Clone the repository, then in its directory:

```console
$ cargo build --release --locked -p server --bin mirrust
$ sudo install -m 0755 target/release/mirrust /usr/local/bin/mirrust
```

`aws-lc-sys` builds with the C compiler alone on x86_64 Linux. If its build step asks for CMake
(it falls back to CMake when that path cannot be used), install it with `sudo apt install cmake`.

The release profile uses thin LTO and one codegen unit, which costs memory at build time. If
the build is killed on a small server, build somewhere else.

### Build elsewhere and copy

Build with the same command on any x86_64 Linux machine whose C library is the same version as
the server's or older (the simplest choice is the same Debian or Ubuntu release), then copy the
one file:

```console
$ scp target/release/mirrust mirror.example.com:/tmp/
$ ssh mirror.example.com sudo install -m 0755 /tmp/mirrust /usr/local/bin/mirrust
```

The binary needs no other files: the HTML pages are compiled in.

## 2. Open the firewall

Open TCP 443 (HTTP/1.1, HTTP/2 and the Let's Encrypt validation) and UDP 443 (HTTP/3), and
nothing else: the validation runs on TCP 443, so port 80 stays closed. With `ufw`:

```console
$ sudo ufw allow 443/tcp
$ sudo ufw allow 443/udp
$ sudo ufw status
```

If `ufw` is not enabled yet, allow SSH (`sudo ufw allow OpenSSH`) before `sudo ufw enable`.
If the hosting provider has its own firewall or security groups, open the same ports there.
Forgetting UDP 443 leaves HTTP/1.1 and HTTP/2 working and HTTP/3 silently unreachable.
Forgetting TCP 443 makes certificate issuance fail.

## 3. Point the name at the server and get a certificate

Create a DNS `A` record for `mirror.example.com` that points at the server's public address
and wait until it resolves. Then start mirrust with `--domain`:

```console
$ sudo mirrust --domain mirror.example.com
```

That is the whole setup: with `--domain` and no `--listen`, mirrust listens on `0.0.0.0:443`
(TCP, and UDP for HTTP/3), orders a certificate from Let's Encrypt, answers the validation on
TCP 443, and renews the certificate about 30 days before it expires. The systemd service in
the next step runs it the same way. The flags involved:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--domain NAME` | none | The host name to certify. Repeat it for up to 4 names on one certificate. Conflicts with `--cert`/`--key`. |
| `--acme-dir DIR` | `./mirrust-acme` | Where the account key and the certificate are kept. |
| `--acme-email ADDR` | none | Contact address for Let's Encrypt. It is used only when the account is created; changing it later does nothing. |
| `--acme-staging` | off | Use the Let's Encrypt staging CA. |

What happens, in order:

1. mirrust prints the notice that `--domain` means accepting the Let's Encrypt Subscriber
   Agreement (<https://letsencrypt.org/repository/>), then starts serving at once.
2. If `--acme-dir` has a valid certificate for exactly these names, it is used and the line
   says so. Otherwise mirrust prints that it is obtaining one. TLS handshakes fail until the
   first certificate arrives, HTTP/3 included, which uses the same certificate.
3. mirrust creates an account (or loads the saved one), orders the certificate, and answers
   the CA's validation connection on TCP 443. A validation connection is recognised by
   ALPN `acme-tls/1`; it is answered with a challenge certificate, is not written to the
   request log and is not counted as a failed connection. It takes a connection slot like any
   other connection.
4. The new certificate is used for new connections at once, with no restart.

On stderr, which the journal keeps, each event is one line:

```
acme: --domain means you accept the Let's Encrypt Subscriber Agreement, https://letsencrypt.org/repository/
acme: obtaining a certificate for mirror.example.com from Let's Encrypt ...; TLS handshakes fail until it arrives (the name must resolve to this server and TCP 443 must be reachable)
acme: issued the certificate for mirror.example.com, valid for 89 days, renewal in 59 days
```

Later lines say `acme: ordering a certificate for ...` when a renewal starts and
`acme: renewed the certificate for ...` when it is done. A failed attempt prints one line with
the CA's error text and the wait before the next attempt, for example:

```
acme: failed: creating the ACME account: client error (Connect): tcp connect error: ...; next attempt in 5 minutes
```

The waits are 5 minutes, then twice as long after each failure, at most 6 hours, and start
again after a success. They survive a restart: the failures are recorded in `last-failure.txt`
in the cache, and a restart waits out the rest of the wait instead of ordering at once, so
restarting while you fix DNS or the firewall does not use up Let's Encrypt's limit of five
failed validations per name and hour (delete the file to try at once). While a renewal fails, the old certificate stays in use. An attempt that
takes longer than 10 minutes counts as failed.

**Try it first with `--acme-staging`.** The staging CA has far higher rate limits, so a
mistake in DNS or the firewall costs little; its certificates are not trusted by browsers
(curl needs `-k`). Staging and production keep separate accounts and certificates in
`--acme-dir`, in the subdirectories `letsencrypt-staging` and `letsencrypt`, so removing
`--acme-staging` afterwards orders a real certificate. Let's Encrypt limits the certificates
and the failed validations per name; see <https://letsencrypt.org/docs/rate-limits/>.

**`--domain auto`.** `--domain auto` uses the name `A-B-C-D.sslip.io` for the machine's public
IPv4 address `A.B.C.D`, so no DNS record of your own is needed. sslip.io is a free third-party
DNS service that answers `A-B-C-D.sslip.io` with `A.B.C.D`; whoever runs it controls what that
name resolves to. mirrust learns its address without asking any service: it opens a UDP
socket towards a documentation address (192.0.2.1) and reads which local address the operating
system chose for it, which sends no packet. If that address is loopback, private (RFC 1918),
link-local, in the carrier-grade NAT range 100.64.0.0/10 or otherwise not routable, mirrust
refuses to start and asks for an explicit `--domain`. That is also what happens on a cloud
server whose public address is a NAT mapping of a private one, so give such a server its name.
`auto` stands for the whole certificate and cannot be combined with other names.

sslip.io is not on the Public Suffix List (checked in the list of 2026-11-20), so Let's Encrypt
counts every `A-B-C-D.sslip.io` name as one registered domain with all other users of the
service, and its limit of 50 certificates per registered domain per week is shared by them. The
sslip.io operators say Let's Encrypt has raised their limit (to 250,000 a week, <https://nip.io>),
but an order can still be refused for that reason; the error text then names the rate limit.
For a server you keep, use a name of your own.

**The cache.** `--acme-dir` is created with mode 0700 if it does not exist, and holds, in a
subdirectory per CA, `account.json` (the ACME account key), `private-key.pem`,
`certificate.pem`, `names.txt` and, after a failed attempt, `last-failure.txt`, all with mode
0600. Keep it private, and keep it across
restarts: a restart that finds a valid certificate for the same names does not ask Let's
Encrypt again. A cached certificate for other names, or one that has expired, is ignored. A
directory that already exists is used as it is, so check its mode.

**IPv6.** If the name has an `AAAA` record, Let's Encrypt connects over IPv6 first and, if
connecting or the TLS handshake over IPv6 fails, tries IPv4 (`va/tlsalpn.go` in Boulder, the Let's Encrypt
software). So a server that listens on IPv4 only (`--listen 0.0.0.0:443`) still validates when
the `AAAA` address does not answer or refuses the connection. It fails when the `AAAA` address
is another machine that does answer on port 443 (a stale record, a CDN), because there is no
retry after a handshake that succeeded: fix or remove that record, or listen on `[::]:443`
(see [Listening address](#listening-address)) when the `AAAA` address is this server's.

**Port.** Let's Encrypt validates on TCP port 443 only. If you give `--listen` another port,
mirrust still starts but prints a warning, and issuance fails unless something forwards TCP 443
to that port.

### What the tests cover, and what they do not

Tested without any certificate authority: the flags and their conflicts, the `auto` name and
each refused address class, the ALPN decision between a validation and a normal connection, a
validation connection being answered with the challenge certificate (checked for the critical
`id-pe-acmeIdentifier` extension and its digest) while leaving no log line and no failure
count, the certificate resolver returning a certificate and switching to a new one, the
renewal time, the cache and its permissions, and the backoff.

Not exercised: the exchange with a real CA, that is, the account, order, validation and
finalisation calls that the `instant-acme` library makes. Nothing here proves that Let's
Encrypt, staging or production, accepts the challenge certificate or that the issued
certificate installs. mirrust has only been started against a CA it could not reach, where it
printed one failure line with a 5-minute wait. Run it once with `--acme-staging` on the real
server before relying on it.

## 4. Install the service

```console
$ sudo install -m 0644 deploy/mirrust.service /etc/systemd/system/mirrust.service
$ sudo sed -i 's/mirror\.example\.com/YOUR.HOST.NAME/g' /etc/systemd/system/mirrust.service
$ sudo systemd-analyze verify /etc/systemd/system/mirrust.service
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now mirrust.service
$ systemctl status mirrust.service
```

The journal should show the `acme:` lines described above and the line the binary prints once
it is listening, and once the CA has validated the name the line that says the certificate was issued:

```console
$ journalctl -u mirrust.service -n 20
... acme: obtaining a certificate for YOUR.HOST.NAME from Let's Encrypt ...
... listening on https://0.0.0.0:443 (TCP and HTTP/3 over UDP)
... acme: issued the certificate for YOUR.HOST.NAME, valid for 89 days, renewal in 59 days
```

What the unit does, in short (every line is commented in the file):

- Runs `/usr/local/bin/mirrust --listen 0.0.0.0:443 --domain YOUR.HOST.NAME --acme-dir
  ${STATE_DIRECTORY} --log /var/log/mirrust/requests.jsonl`. Add `--acme-email` and, for a first
  try, `--acme-staging` to the `ExecStart=` line.
- Runs as a dynamic user that exists only while the service runs, with
  `CAP_NET_BIND_SERVICE` as its only capability, so it can bind TCP 443 and UDP 443 and nothing
  else that needs privileges.
- Keeps the ACME account key and the certificate in `/var/lib/mirrust` (`StateDirectory=` with
  mode 0700). With `DynamicUser=` the real directory is `/var/lib/private/mirrust`, and
  `/var/lib/mirrust` is a link to it. The directory stays when the service stops, so a restart
  does not order a certificate again.
- Mounts the file system read-only for the service, except `/var/log/mirrust` and
  `/var/lib/mirrust`.
- Limits memory to 256 MiB and open files to 65536, and restarts the service on failure.
- Stops the service with SIGINT. mirrust flushes the request log and exits with status 0 on
  SIGINT and on SIGTERM alike; the unit names SIGINT so that systemd counts the exit as clean.

Review the sandbox with `systemd-analyze security mirrust.service`.

### Listening address

`--listen` takes one socket address. `0.0.0.0:443` accepts IPv4 only. To accept IPv6 as well,
change it to `[::]:443`: with the Linux default `net.ipv6.bindv6only=0`, that socket also
accepts IPv4, and IPv4 clients then appear in reports and in the log as IPv4-mapped addresses
such as `[::ffff:203.0.113.7]:51234`.

Keep the port at 443 or change it in the unit, not with a port redirect: responses carry
`Alt-Svc: h3=":PORT"` with the port mirrust itself listens on, and clients use that port for
HTTP/3.

### Output in the journal

Besides the request log, mirrust prints one line per request on stdout, and the journal
stores it. To keep only stderr in the journal, add a drop-in with `sudo systemctl edit
mirrust.service`:

```ini
[Service]
StandardOutput=null
```

## 5. Verify

From another machine:

```console
$ curl -s --http1.1 -o /dev/null -w '%{http_version} %{http_code}\n' https://mirror.example.com/api/all
1.1 200
$ curl -s --http2 -o /dev/null -w '%{http_version} %{http_code}\n' https://mirror.example.com/api/all
2 200
$ curl -s --http2 https://mirror.example.com/api/clean
$ curl -s --http2 -D - -o /dev/null https://mirror.example.com/api/clean | grep -i alt-svc
alt-svc: h3=":443"; ma=86400
```

HTTP/3 needs a curl built with HTTP/3 support; `curl --version` must list `HTTP3` under
`Features`:

```console
$ curl -s --http3-only -o /dev/null -w '%{http_version} %{http_code}\n' https://mirror.example.com/api/all
3 200
```

Without such a curl, open `https://mirror.example.com/` in a browser and reload the page: after
the first response the browser may switch to HTTP/3 because of the `Alt-Svc` header, and the
page then reports `h3`.

If HTTP/2 works and HTTP/3 times out, check UDP 443 in every firewall on the path, and on the
server:

```console
$ sudo ss -lntup | grep ':443 '
```

It should list one `tcp` and one `udp` socket owned by `mirrust`.

## 6. Rotate the request log

The unit writes the request log to `/var/log/mirrust/requests.jsonl`, one JSON object per
line (see "Request log" in the [Reference](reference.md#request-log)). With the unit's dynamic user
the real location is `/var/log/private/mirrust/`, and `/var/log/mirrust` is a symbolic
link to it; read the log as root.

mirrust opens the file once at start, in append mode, and keeps it open. It does not reopen
the file on a signal. Rotation by renaming therefore does not work on its own: the server would
keep writing to the renamed file. Use logrotate's `copytruncate`, which copies the file and then
empties it in place. Because the file is open in append mode, the next line lands at the start
of the emptied file.

```console
$ sudo install -m 0644 deploy/mirrust.logrotate /etc/logrotate.d/mirrust
$ sudo logrotate --debug /etc/logrotate.d/mirrust
```

The rules rotate weekly, keep eight files and compress all but the newest. Lines that
mirrust writes between logrotate's copy and its truncation are lost. The window is short
(mirrust writes at most once a second, or every 256 lines under load), but it exists.

If no line may be lost, rotate by renaming and restart the service instead: replace
`copytruncate` in the rules with

```
    postrotate
        systemctl restart mirrust.service
    endscript
```

A restart writes out everything queued, then the new process creates a fresh file. Connections
open at that moment are dropped.

If a write to the log fails (the disk is full, say), mirrust prints the error on stderr and
stops logging for good while it keeps serving. Restart the service once the cause is fixed.

The log contains client addresses and `User-Agent` strings. Choose `rotate` and the schedule to
match how long you are allowed and willing to keep them.

## 7. Check the certificate and its renewal

mirrust renews the certificate by itself, about 30 days before it expires, and starts using the
new one for new connections without a restart; the journal gets an `acme: renewed ...` line.
To see which certificate is being served:

```console
$ echo | openssl s_client -connect mirror.example.com:443 -servername mirror.example.com 2>/dev/null \
    | openssl x509 -noout -issuer -dates
```

The renewal needs TCP 443 to be reachable from the internet and the name to still point at
the server, as the first issuance did. If renewals fail, the `acme: failed:` lines in the
journal say why; the certificate in use stays until it expires.

## 8. Update

Replace the binary and restart:

```console
$ sudo install -m 0755 mirrust /usr/local/bin/mirrust
$ sudo systemctl restart mirrust.service
```

With `install.sh`, run it again (add `--version vX.Y.Z` for a particular release), then restart
the service; the unit stays as it is. `sudo ./mirrust install` with the new binary and the
same flags replaces the binary and restarts the service in one go.

## Alternative: certificate files

Use this to keep certbot, a certificate from another CA, or a certificate you manage yourself.
mirrust then does no ACME: give it `--cert` and `--key`, as before (these conflict with
`--domain`).

**Firewall.** TCP 443 and UDP 443 as in step 2. With certbot's standalone mode also open TCP 80:
`sudo ufw allow 80/tcp`.

**Obtain a certificate.** mirrust does not listen on port 80 and does not answer HTTP-01
challenges, so with certbot two ways work:

**Standalone (HTTP-01).** certbot starts its own temporary server on port 80, which is free
because mirrust does not use it. Port 80 must be reachable from the internet when the
certificate is issued and at every renewal.

```console
$ sudo apt install certbot
$ sudo certbot certonly --standalone -d mirror.example.com
```

**DNS challenge (DNS-01).** No inbound port is needed. Use the certbot plugin for your DNS
provider so that renewal is automatic, for example:

```console
$ sudo apt install certbot python3-certbot-dns-cloudflare
$ sudo certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /root/cloudflare.ini -d mirror.example.com
```

`certbot certonly --manual --preferred-challenges dns` also works but has to be repeated by hand
before every expiry.

Either way the files are:

```
/etc/letsencrypt/live/mirror.example.com/fullchain.pem
/etc/letsencrypt/live/mirror.example.com/privkey.pem
```

They stay readable by root only. The service does not read them directly; see the next part.

**The unit.** In `/etc/systemd/system/mirrust.service`, replace the `--domain` and `--acme-dir`
arguments of `ExecStart=` with the two certificate arguments, and add the two `LoadCredential=`
lines. `StateDirectory=` is not needed any more and can stay or go:

```ini
ExecStart=/usr/local/bin/mirrust \
    --listen 0.0.0.0:443 \
    --cert ${CREDENTIALS_DIRECTORY}/cert.pem \
    --key ${CREDENTIALS_DIRECTORY}/key.pem \
    --log /var/log/mirrust/requests.jsonl

LoadCredential=cert.pem:/etc/letsencrypt/live/mirror.example.com/fullchain.pem
LoadCredential=key.pem:/etc/letsencrypt/live/mirror.example.com/privkey.pem
```

`${CREDENTIALS_DIRECTORY}` is set by systemd because of `LoadCredential=`: systemd reads both
files as root at start and gives the service private read-only copies, so the service user
never needs access to `/etc/letsencrypt`. This is the variant that ran on the Ubuntu server
described at the top of this page, with a self-signed certificate instead of the certbot
files.

**Renew the certificate.** mirrust reads the certificate and key once, at start, and systemd
copies them for the service at start as well. A renewed certificate is used only after a
restart. The certbot package installs a timer that renews certificates automatically. Add a
deploy hook, which certbot runs after each successful renewal:

```console
$ sudo tee /etc/letsencrypt/renewal-hooks/deploy/mirrust.sh >/dev/null <<'EOF'
#!/bin/sh
systemctl restart mirrust.service
EOF
$ sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/mirrust.sh
```

Check that renewal itself works with `sudo certbot renew --dry-run` (a dry run does not run
deploy hooks). With the standalone method, TCP 80 must be open for it. The restart drops the
connections open at that moment and the service is listening again right after.

## Docker

A container image and a Compose file are described in [docker.md](docker.md): a static binary
on a distroless image, run as UID 10001 with no capabilities, built and smoke-tested in CI. With
the built-in ACME client the whole deployment is `docker run` with `--domain` and a volume.

## What is not there yet

- **TCP SYN fingerprinting.** The workspace has a SYN parser (`crates/tcpip`), but the server
  does not capture SYN packets, so `tcpip` in every report is `{"ip": {}, "tcp": {}}` and the
  `audit` check `tcp_os` is reported as not measured. The plan is the Linux socket options
  `TCP_SAVE_SYN` and `TCP_SAVED_SYN`; see [architecture.md](architecture.md#known-gaps). If that
  works as planned, it needs no extra privileges and the unit would not have to change. The
  fallback described there, a packet socket, would need `CAP_NET_RAW` and `AF_PACKET` added to
  the unit.
- **Nothing on port 80.** There is no HTTP listener and no redirect to HTTPS. The ACME
  validation does not need one.
- **No reload.** With certificate files, a new certificate needs a restart; so does a log file
  rotated by renaming. A certificate from `--domain` is replaced while the server runs.
- **ACME is Let's Encrypt only, one challenge type.** There is no flag for another CA, no
  wildcard names (they need DNS validation) and no HTTP-01 or DNS-01. A name that cannot reach
  mirrust on TCP 443 cannot get a certificate.
- **No IP block list.** Filter in the firewall if you need to.

The full list of known gaps is in [architecture.md](architecture.md#known-gaps).
