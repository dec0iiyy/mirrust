#!/bin/sh
# Smoke test of a mirrust binary: it prints its usage, then serves /api/clean over HTTPS.
#
#   smoke-test.sh BINARY
#
# POSIX sh, so that it runs in debian:12-slim and in alpine as well as on a macOS runner.
# smoke-test-linux.sh runs it inside throwaway containers. It needs curl; when curl is
# missing it installs it with apt-get or apk, which needs root and a network, so run it
# on a developer machine only where curl exists. SMOKE_PORT (default 8443) picks the port.
set -eu

bin=${1:?usage: smoke-test.sh BINARY}
port=${SMOKE_PORT:-8443}
log=$(mktemp)
out=$(mktemp)

echo "--- $bin --help"
"$bin" --help

if ! command -v curl >/dev/null 2>&1; then
    echo "--- installing curl"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends curl ca-certificates >/dev/null
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl >/dev/null
    else
        echo "curl is missing and there is no package manager to install it" >&2
        exit 1
    fi
fi

echo "--- start on 127.0.0.1:$port"
"$bin" --listen "127.0.0.1:$port" >"$log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT

# -k: the certificate is self-signed. The retries cover the time the server needs to bind.
# %{http_version} proves that ALPN negotiated HTTP/2 and not only that TLS worked.
if ! version=$(curl -sS -k --retry 20 --retry-delay 1 --retry-connrefused --max-time 10 \
        --fail -o "$out" -w '%{http_version}' "https://127.0.0.1:$port/api/clean"); then
    echo "request failed; server output:" >&2
    cat "$log" >&2
    exit 1
fi
# Another server on the port would answer in place of the binary under test, which then
# exits because it cannot bind; give it a moment to do so.
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then
    echo "the server under test has exited; server output:" >&2
    cat "$log" >&2
    exit 1
fi
echo "HTTP version: $version"
if [ "$version" != 2 ]; then
    echo "expected HTTP/2, got HTTP/$version" >&2
    exit 1
fi
if ! grep -q '"audit"' "$out"; then
    echo "the response has no audit field:" >&2
    cat "$out" >&2
    exit 1
fi
echo "response: $(head -c 200 "$out")"

# SIGINT is what the systemd unit sends; the server writes its request log and exits.
kill -INT "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
echo "--- ok: $bin"
