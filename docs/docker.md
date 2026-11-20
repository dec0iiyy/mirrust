# Running mirrust in Docker

mirrust is published as a small container image, `ghcr.io/dec0iiyy/mirrust`, for `linux/amd64`
and `linux/arm64`. It holds one static binary and runs as a non-root user with no
capabilities.

> **Status: nothing in this file has been run.** The Dockerfile, the compose file and the
> workflow were written on a machine without Docker. They were checked by reading, by
> `actionlint` and by looking up the base images in the registries, nothing more. The
> [Status](#status) section at the end lists what is untested. Treat every command here as
> unverified until the `Docker` workflow has run once on GitHub and passed.

## Run it with `docker run`

```console
$ docker run -d --name mirrust --restart unless-stopped \
    -p 443:443/tcp -p 443:443/udp \
    --sysctl net.ipv4.ip_unprivileged_port_start=0 \
    --cap-drop ALL --security-opt no-new-privileges:true --read-only \
    --memory 512m --pids-limit 512 \
    -v mirrust-data:/data \
    ghcr.io/dec0iiyy/mirrust:<version> --listen 0.0.0.0:443 --log /data/requests.jsonl
```

Replace `<version>` with a release such as `1.2.3`. There is a tag per version, one per
`MAJOR.MINOR` and `latest`; pin a version (or a digest) for a server you keep running.

What each part does:

| Option | Why |
| --- | --- |
| `-p 443:443/tcp -p 443:443/udp` | TCP serves HTTP/1.1 and HTTP/2, UDP serves HTTP/3. Both on the same port number; see [Why 443 on both sides](#why-443-on-both-sides). |
| `--sysctl net.ipv4.ip_unprivileged_port_start=0` | Lets the non-root user in the container bind port 443; see [Binding port 443 as a non-root user](#binding-port-443-as-a-non-root-user). |
| `--cap-drop ALL` | The process needs no Linux capability. |
| `--security-opt no-new-privileges:true` | The process cannot gain privileges. |
| `--read-only` | The root file system is read-only; only the volume is writable. |
| `--memory 512m --pids-limit 512` | Limits. They are a guess and have not been measured under load: raise them if the container is killed or cannot start threads. |
| `-v mirrust-data:/data` | A named volume for the request log (and, later, a certificate cache). It starts out owned by the image's user, UID 10001. |
| `--listen 0.0.0.0:443` | The default of the image; the server must listen on all interfaces of the container for the published ports to reach it. |
| `--log /data/requests.jsonl` | One JSON line per request and per failed TLS handshake. Leave it out for no log. |

Without `--cert` and `--key` the server answers with a self-signed certificate for
`localhost`, which is enough to try it with `curl -k https://localhost/api/clean`. For a real
host name, give it the certificate chain and key. The files under `/etc/letsencrypt` can be
read by root only, so copy them to a directory UID 10001 can read:

```console
$ docker run -d --name mirrust --restart unless-stopped \
    -p 443:443/tcp -p 443:443/udp \
    --sysctl net.ipv4.ip_unprivileged_port_start=0 \
    --cap-drop ALL --security-opt no-new-privileges:true --read-only \
    --memory 512m --pids-limit 512 \
    -v mirrust-data:/data \
    -v /srv/mirrust/certs:/certs:ro \
    ghcr.io/dec0iiyy/mirrust:<version> \
    --listen 0.0.0.0:443 --log /data/requests.jsonl \
    --cert /certs/fullchain.pem --key /certs/privkey.pem
```

A renewed certificate is read at start only, so restart the container after renewing
(`docker restart mirrust`). The flags are described in [reference.md](reference.md).

## Run it with Docker Compose

`deploy/compose.yaml` sets the same options. From the repository root:

```console
$ docker compose -f deploy/compose.yaml up -d --build
```

It builds the image from `deploy/Dockerfile`. To use the published image instead, in
`deploy/compose.yaml` replace the `build:` block and the `image:` line with
`image: ghcr.io/dec0iiyy/mirrust:<version>`. The commented lines at the end of `command:` and
the commented `./certs:/certs:ro` volume turn on a certificate and key; the file says what to
change. `docker compose -f deploy/compose.yaml down` keeps the volume, and `down -v` deletes it.

## Why 443 on both sides

The server advertises HTTP/3 with an `Alt-Svc` header on its HTTP/1.1 and HTTP/2 answers,
`h3=":<port>"`, where `<port>` is the port it listens on **inside the container**, 443. A client
that reads it then tries UDP on that port of the same host. If the container's 443 were
published as another host port, for example `-p 8443:443`, the header would send HTTP/3
clients to port 443 of the host, where nothing answers (or something else does). So publish
the container's TCP and UDP port 443 as the host's TCP and UDP 443, and open both in the
firewall. If the server must listen on another port, change `--listen` and publish that same
number on both sides.

## Binding port 443 as a non-root user

Port 443 is below 1024, which an unprivileged process may not bind unless the kernel setting
`net.ipv4.ip_unprivileged_port_start` allows it. There are two ways to allow it for the
container, and the image uses the first:

1. **The sysctl** `net.ipv4.ip_unprivileged_port_start=0`, set for the container's own network
   namespace with `--sysctl` or `sysctls:`. Docker Engine sets it to `0` by itself for a
   container with its own network namespace: the code that builds the container's runtime
   spec, `daemon/oci_linux.go` in moby/moby, does `s.Linux.Sysctl["net.ipv4.ip_unprivileged_port_start"] = "0"`
   when the network mode is private, with the comment "allow opening any port less than 1024
   without CAP_NET_BIND_SERVICE". It is not set with `--network host`, on another runtime, or
   on Kubernetes, and the Docker documentation notes that non-root containers could not bind
   such ports before Engine 20.10. This documentation sets the option explicitly, so the
   container does not depend on the engine's default.
2. **The capability** `NET_BIND_SERVICE` (`cap_add`). It does not do what it looks like for a
   process that does not run as root: Docker puts the added capability in the container's
   bounding set but not in the ambient set, so a non-root process does not get it, unless the
   binary carries a file capability. The image does not (it has no tools to set one). This is
   the behaviour of Docker as commonly reported and not something this repository has tested.

The sysctl is the more robust choice because it needs no capability at all, so
`cap_drop: [ALL]` stays complete. If you cannot set it (with `--network host`, for example,
the container shares the host's network namespace and Docker sets nothing), either run
mirrust on a port above 1023 inside the container and publish that same number on both sides
(`--listen 0.0.0.0:8443`, `-p 8443:8443/tcp -p 8443:8443/udp`; the host port is then not 443),
or set `net.ipv4.ip_unprivileged_port_start` on the host. Running the container as root would
also work and is not recommended.

## What is in the image

| Path | Content |
| --- | --- |
| `/mirrust` | The server, statically linked against musl (see below), `ENTRYPOINT`. |
| `/data` | An empty directory owned by UID 10001, declared as a `VOLUME`, and the working directory. |
| the rest | `gcr.io/distroless/static-debian13:nonroot`: CA certificates, time zone data, `/etc/passwd` and the like. No shell, no package manager, no `curl`. |

- **User.** `USER 10001:10001`, the same UID `docs/deploy.md` uses for certificate files. The
  user has no `/etc/passwd` entry, which the server does not need.
- **Defaults.** `CMD ["--listen", "0.0.0.0:443"]`: the arguments of `docker run ... <image>`
  replace it, so give `--listen` again as in the examples above.
- **Ports.** `EXPOSE 443/tcp 443/udp`. `EXPOSE` does not publish anything; `-p` does.
- **Labels.** `org.opencontainers.image.source` points at this repository, which is what links
  the package to it on GHCR.
- **Why musl.** The build stage compiles for `x86_64-unknown-linux-musl` or
  `aarch64-unknown-linux-musl`, chosen from Docker's `TARGETARCH`, with `musl-tools` installed
  in the build stage. That gives a self-contained binary that needs no C library in the final
  image, so the base can be distroless `static` (a few megabytes). The C code of `aws-lc-sys`
  (the crypto behind rustls and quinn) has pregenerated bindings for both musl targets in the
  locked version, 0.47.0, so no `bindgen` or `clang` is needed; the sources of that crate say so.
  Whether it compiles and links in the Docker build stage has not been run, see
  [Status](#status). The known costs of musl are a slower memory allocator than glibc's and a
  simpler DNS resolver; neither matters for a server that makes no outgoing connections.
  **If the musl build fails in CI**, fall back to a glibc build: drop `musl-tools`, the
  `rustup target add` and `--target`, copy `target/release/mirrust`, and use
  `gcr.io/distroless/cc-debian13:nonroot` as the final image.
- **Pinned bases.** The build stage is `rust:1.99.1-trixie` and the final stage is
  `gcr.io/distroless/static-debian13:nonroot`, each pinned by tag and by the digest of its
  multi-platform index. `apt-get install musl-tools` is not pinned to a version, so the build
  is not byte-for-byte reproducible.
- **Size.** The workflow prints the image size for each platform in its log and job summary;
  no figure is quoted here because none has been measured.
- **No `HEALTHCHECK`.** A health check has to run a command inside the container, and the
  image has no shell, no `curl`, nothing to run besides the server, which has no `--health`
  mode. Check from outside instead: `curl -k https://<host>/api/clean`, or a monitor that
  requests it. `restart: unless-stopped` restarts the container if the process exits.

## Logs

The server prints its listening line and a failure summary on standard output and standard
error:

```console
$ docker logs mirrust
$ docker logs -f --tail 100 mirrust
```

The request log (`--log`) is a file in the volume. The image has no shell, so copy it out of
the container (which also works when the container is stopped):

```console
$ docker cp mirrust:/data/requests.jsonl - | tar -xO | tail
```

The log is only ever appended to, and the server reopens it at start only. To rotate it,
stop the container, move the file, and start the container again.

## Updating the image

```console
$ docker pull ghcr.io/dec0iiyy/mirrust:<new-version>
$ docker rm -f mirrust
$ docker run ...   # the same command with the new tag
```

With Compose, change the tag in `deploy/compose.yaml`, then
`docker compose -f deploy/compose.yaml pull` and `docker compose -f deploy/compose.yaml up -d`
(with `build:`, `up -d --build` after `git pull`). The volume survives. The connections open at
that moment are dropped and the server is back right after.

### Checking where an image came from

A release image has a build provenance attestation: a signed statement that this image was
built by this repository's `Docker` workflow from the tag's commit. Check it with the GitHub
CLI, which needs no keys:

```console
$ gh attestation verify oci://ghcr.io/dec0iiyy/mirrust:<version> --repo dec0iiyy/mirrust
```

To pin the exact bytes, take the digest the command prints, or
`docker buildx imagetools inspect ghcr.io/dec0iiyy/mirrust:<version>`, and run
`ghcr.io/dec0iiyy/mirrust@sha256:<digest>`. There is no cosign signature of its own and no
SBOM attached: BuildKit's per-platform attestations are switched off because the two platform
images are joined afterwards (see `.github/workflows/docker.yml`). The attestation covers the
joined image, not the per-platform images.

### Updating the pins of the base images

Move the tag and the digest of both `FROM` lines in `deploy/Dockerfile` together. A digest can
be read from the registry without pulling anything:

```console
$ TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/rust:pull" | jq -r .token)
$ curl -sI -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.oci.image.index.v1+json" \
    https://registry-1.docker.io/v2/library/rust/manifests/<tag> | grep -i docker-content-digest
$ curl -sI -H "Accept: application/vnd.oci.image.index.v1+json" \
    https://gcr.io/v2/distroless/static-debian13/manifests/nonroot | grep -i docker-content-digest
```

The Rust version in the tag must stay at or above `rust-version` in `Cargo.toml`.

## Built-in ACME (Let's Encrypt)

> **Placeholder for the maintainer.** This section is to be filled in when built-in ACME is
> merged. What follows is what the flag names suggest and is **not verified**: it was written
> before the code exists and may be wrong in every detail.

The server is expected to get and renew its certificate itself, through these flags:
`--domain` (the host name), `--acme-dir` (the certificate cache directory), `--acme-email`
(a contact address) and `--acme-staging` (use Let's Encrypt's staging service while testing).
The image and `deploy/compose.yaml` are prepared for it in two ways only: `/data` is a
writable volume owned by the server's user, which is the natural place for `--acme-dir`
(for example `--acme-dir /data/acme`), and the image contains CA certificates.

To be checked against the merged code and the docs of that change before this section is
written:

- how the certificate is obtained (the ACME challenge type, and so which port must be
  reachable: the server has no listener on port 80 today, and TLS-ALPN-01 would use 443);
- whether the `--sysctl` and the `443:443` ports in this file still suffice, or a port 80
  mapping is needed;
- whether the server resolves names and makes outgoing connections, which a `read_only`
  root and the resolver of the musl build must support;
- the exact flags, their defaults and how `--cert`/`--key` combine with them;
- how the cache directory's ownership works with a named volume and with a bind mount;
- the `command:` of `deploy/compose.yaml` and the `docker run` line for the ACME case;
- whether a staging run should come first (`--acme-staging`), to stay inside Let's Encrypt's
  rate limits.

## Status

Nothing that needs Docker has been run, because the machine the files were written on has no
Docker. Until the `Docker` workflow has run once on GitHub:

- **Not run:** `docker build -f deploy/Dockerfile .` on either platform, in particular the
  musl build of `aws-lc-sys` and the linking step.
- **Not run:** the image itself: that it starts, binds 443 as UID 10001 with all capabilities
  dropped, serves HTTP/1.1, HTTP/2 and HTTP/3, writes its log to `/data`, and exits with code 0
  on `docker stop`.
- **Not run:** `deploy/compose.yaml` (Docker Compose has not parsed it; only a YAML parser has).
- **Not run:** the publish and merge jobs, the `gh attestation verify` command, the tags and
  the `latest` rule. The package may be private after its first publish: check its visibility
  in the GitHub package settings.
- **Not tested:** HTTP/3 over the published UDP port. The workflow's runner has no HTTP/3
  `curl`, so its smoke test covers TCP only (HTTP/2, HTTP/1.1 and the `Alt-Svc` header).
- **Not measured:** the image size and the memory and process limits.
- **Not verified:** the claim that `cap_add: NET_BIND_SERVICE` does not work for a non-root
  user (see above); the sysctl route is read from Docker's source, not exercised here.
- **Checked:** the workflow with `actionlint` 1.7.12 (which runs `shellcheck` on the shell
  steps); the base image tags and digests, and that both are multi-platform for `amd64` and
  `arm64`, through the registries' APIs; that the build context in `.dockerignore` is enough
  for `cargo check --locked --bin mirrust`; and the pinned action versions and commit
  hashes through the GitHub API.

The first run of the workflow, on a pull request, is the real test of the image: expect to fix
things it finds.
