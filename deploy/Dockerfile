# Build from the repository root:
#
#   docker build -f deploy/Dockerfile -t mirrust .
#
# The build stage and the runtime stage are the same Debian release, so the binary runs
# against the C library it was linked with.

FROM rust:1.99.1-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p server --bin mirrust

FROM debian:13.7-slim
COPY --from=build /src/target/release/mirrust /usr/local/bin/mirrust
# A fixed numeric user with no account, no home directory and no shell.
USER 10001:10001
# TCP serves HTTP/1.1 and HTTP/2; UDP on the same port serves HTTP/3.
EXPOSE 443/tcp 443/udp
ENTRYPOINT ["/usr/local/bin/mirrust"]
# Arguments given to "docker run" replace this default.
CMD ["--listen", "0.0.0.0:443"]
