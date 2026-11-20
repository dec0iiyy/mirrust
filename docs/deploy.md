# Deploying mirrust

This page sets up mirrust on a Debian or Ubuntu server (x86_64, systemd) as a sandboxed
service on TCP and UDP port 443, with a certificate from Let's Encrypt. `mirror.example.com`
stands for your host name throughout.

These steps have not been run on a Linux host yet. That covers the commands on this page, the
systemd unit, the logrotate rules and the Docker image. The server itself has been run only on
macOS. Check each step, and the output of `systemd-analyze verify` and `systemd-analyze
security`, before you rely on it.

You need:

- A server with a public address and a DNS `A` record for the host name that points to it.
- systemd 247 or later: Debian 11, Ubuntu 22.04, or newer. Check with `systemctl --version`.
- Port 443 free for both TCP and UDP. mirrust terminates TLS itself. Do not put a
  TLS-terminating reverse proxy or CDN in front of it: mirrust would then report the proxy's
  TLS and HTTP/2 fingerprint, not the client's.

Files used below are in [`deploy/`](../deploy): `mirrust.service`, `mirrust.logrotate`
and `Dockerfile`.

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

Open TCP 443 (HTTP/1.1 and HTTP/2) and UDP 443 (HTTP/3). If you will obtain the certificate
with certbot's standalone mode, also open TCP 80. With `ufw`:

```console
$ sudo ufw allow 443/tcp
$ sudo ufw allow 443/udp
$ sudo ufw allow 80/tcp
$ sudo ufw status
```

If `ufw` is not enabled yet, allow SSH (`sudo ufw allow OpenSSH`) before `sudo ufw enable`.
If the hosting provider has its own firewall or security groups, open the same ports there.
Forgetting UDP 443 leaves HTTP/1.1 and HTTP/2 working and HTTP/3 silently unreachable.

## 3. Obtain a certificate

mirrust does not listen on port 80 and does not answer ACME challenges, so the certificate
comes from a separate client. Two ways with certbot:

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

They stay readable by root only. The service does not read them directly; see the next step.

## 4. Install the service

```console
$ sudo install -m 0644 deploy/mirrust.service /etc/systemd/system/mirrust.service
$ sudo sed -i 's/mirror\.example\.com/YOUR.HOST.NAME/g' /etc/systemd/system/mirrust.service
$ sudo systemd-analyze verify /etc/systemd/system/mirrust.service
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now mirrust.service
$ systemctl status mirrust.service
```

The journal should show the line the binary prints once it is listening:

```console
$ journalctl -u mirrust.service -n 20
... listening on https://0.0.0.0:443 (TCP and HTTP/3 over UDP)
```

What the unit does, in short (every line is commented in the file):

- Runs `/usr/local/bin/mirrust --listen 0.0.0.0:443 --cert ... --key ... --log
  /var/log/mirrust/requests.jsonl`.
- Runs as a dynamic user that exists only while the service runs, with
  `CAP_NET_BIND_SERVICE` as its only capability, so it can bind TCP 443 and UDP 443 and nothing
  else that needs privileges.
- Passes the certificate and key with `LoadCredential=`: systemd reads both files as root at
  start and gives the service private read-only copies. The service user never needs access
  to `/etc/letsencrypt`.
- Mounts the file system read-only for the service, except `/var/log/mirrust`.
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

## 7. Renew the certificate

mirrust reads the certificate and key once, at start, and systemd copies them for the service
at start as well. A renewed certificate is used only after a restart.

The certbot package installs a timer that renews certificates automatically. Add a deploy hook,
which certbot runs after each successful renewal:

```console
$ sudo tee /etc/letsencrypt/renewal-hooks/deploy/mirrust.sh >/dev/null <<'EOF'
#!/bin/sh
systemctl restart mirrust.service
EOF
$ sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/mirrust.sh
```

Check that renewal itself works with `sudo certbot renew --dry-run` (a dry run does not run
deploy hooks). With the standalone method, TCP 80 must be open for it.

The restart drops the connections open at that moment and the service is listening again right
after. To see which certificate is being served:

```console
$ echo | openssl s_client -connect mirror.example.com:443 -servername mirror.example.com 2>/dev/null \
    | openssl x509 -noout -dates
```

## 8. Update

Replace the binary and restart:

```console
$ sudo install -m 0755 mirrust /usr/local/bin/mirrust
$ sudo systemctl restart mirrust.service
```

## Docker

`deploy/Dockerfile` builds the binary in a Rust image and copies it into a Debian slim image
that runs it as a non-root user. Build from the repository root:

```console
$ docker build -f deploy/Dockerfile -t mirrust .
```

Run it with both protocols published, and the certificate and key in a directory that UID 10001
can read (the files under `/etc/letsencrypt` are readable by root only, so copy them):

```console
$ docker run -d --name mirrust --restart unless-stopped \
    -p 443:443/tcp -p 443:443/udp \
    -v /srv/mirrust/certs:/certs:ro \
    mirrust --listen 0.0.0.0:443 --cert /certs/fullchain.pem --key /certs/privkey.pem
```

Notes:

- Without `--cert` and `--key` the container serves a self-signed certificate for `localhost`.
- Publish the container's port 443 as the host's port 443. The `Alt-Svc` header names the port
  mirrust listens on inside the container, so a mapping such as `-p 443:8443` would point
  HTTP/3 clients at the wrong port.
- The process is not root and has no capabilities. Docker Engine 20.10 and later lets such a
  process bind port 443 inside a container's own network namespace. On another runtime, or if
  the bind is refused, add `--sysctl net.ipv4.ip_unprivileged_port_start=0`.
- For a request log, mount a directory that UID 10001 can write and add `--log` with a path
  inside it.

## What is not there yet

- **TCP SYN fingerprinting.** The workspace has a SYN parser (`crates/tcpip`), but the server
  does not capture SYN packets, so `tcpip` in every report is `{"ip": {}, "tcp": {}}` and the
  `audit` check `tcp_os` is reported as not measured. The plan is the Linux socket options
  `TCP_SAVE_SYN` and `TCP_SAVED_SYN`; see [architecture.md](architecture.md#known-gaps). If that
  works as planned, it needs no extra privileges and the unit would not have to change. The
  fallback described there, a packet socket, would need `CAP_NET_RAW` and `AF_PACKET` added to
  the unit.
- **Nothing on port 80.** There is no HTTP listener and no redirect to HTTPS.
- **No reload.** A new certificate, and a log file rotated by renaming, both need a restart.
- **No IP block list.** Filter in the firewall if you need to.

The full list of known gaps is in [architecture.md](architecture.md#known-gaps).
