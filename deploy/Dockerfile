# Build from the repository root:
#
#   docker build -f deploy/Dockerfile -t mirrust .
#
# Two stages. The build stage compiles a static musl binary for the architecture it runs on
# (a native build per platform, no emulation), and the final image holds that one binary
# and nothing else: no shell, no package manager, no curl. See docs/docker.md.
#
# Every base image is pinned by tag and by the digest of its multi-platform index. To move to
# a newer one, change the tag and the digest together (docs/docker.md, "Updating the pins").

FROM rust:1.99.1-trixie@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS build

# Set by BuildKit to the platform being built: amd64 or arm64.
ARG TARGETARCH

# musl-tools provides musl-gcc, the C compiler for aws-lc-sys (rustls and quinn use it).
# aws-lc-sys has pregenerated bindings for both musl targets, so bindgen is not needed.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH '$TARGETARCH': expected amd64 or arm64" >&2; exit 1 ;; \
    esac > /rust-target \
    && rustup target add "$(cat /rust-target)"

# Compile the C code of aws-lc-sys for the musl target with musl-gcc, not with the glibc gcc.
ENV CC_x86_64_unknown_linux_musl=musl-gcc \
    CC_aarch64_unknown_linux_musl=musl-gcc

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY corpus/clients.jsonl ./corpus/clients.jsonl
COPY deploy/mirrust.service ./deploy/mirrust.service
RUN cargo build --release --locked --bin mirrust --target "$(cat /rust-target)" \
    && install -D -m 0555 "target/$(cat /rust-target)/release/mirrust" /out/mirrust
# The state directory, empty, for the final image to copy with its owner set.
RUN install -d -m 0750 /out/data


FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

LABEL org.opencontainers.image.title="mirrust" \
      org.opencontainers.image.description="HTTPS server that reports the TLS, HTTP/2 and HTTP/3 fingerprints of the client" \
      org.opencontainers.image.source="https://github.com/dec0iiyy/mirrust" \
      org.opencontainers.image.licenses="GPL-3.0-only"

COPY --from=build /out/mirrust /mirrust
# Writable state: the request log now, the certificate cache later. A named volume mounted
# here starts with this owner; a bind mount keeps the host directory's owner.
COPY --from=build --chown=10001:10001 /out/data /data
VOLUME /data

# A fixed numeric user, the same as in docs/deploy.md. It has no entry in /etc/passwd, which
# the server does not need.
USER 10001:10001
WORKDIR /data

# TCP serves HTTP/1.1 and HTTP/2; UDP on the same port serves HTTP/3. Port 443 is below 1024,
# so run the container with net.ipv4.ip_unprivileged_port_start=0 (compose.yaml and
# docs/docker.md do): the process has no capabilities.
EXPOSE 443/tcp 443/udp
ENTRYPOINT ["/mirrust"]
# Arguments given to "docker run" replace this default.
CMD ["--listen", "0.0.0.0:443"]
