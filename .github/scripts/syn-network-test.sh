#!/usr/bin/env bash
# Checks the TCP SYN capture over a connection between two different addresses.
#
#   sudo syn-network-test.sh BINARY
#
# The test in crates/server/tests/api.rs reads the SYN of a loopback connection. This one
# puts the server and the client in two network namespaces joined by a veth pair, server on
# 10.77.0.1, client (curl) on 10.77.0.2, so the SYN is a real one from the client's network
# stack, sent over an interface. It checks the `tcpip` fields and the audit checks `tcp_os`
# and `tcp_mss`, including that a Linux client claiming a Windows User-Agent fails `tcp_os`.
#
# Linux only, as root (it creates namespaces), with ip (iproute2), curl and jq. It builds
# nothing: BINARY is a mirrust built for this machine. It leaves no namespace or process
# behind, also when it fails, and prints the server output when it fails.
set -euo pipefail

bin=${1:?usage: syn-network-test.sh BINARY}
if [[ ! -x $bin ]]; then
    echo "not an executable file: $bin" >&2
    exit 2
fi
bin=$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")

for tool in ip curl jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "$tool is missing" >&2
        exit 2
    fi
done
if [[ $(id -u) -ne 0 ]]; then
    echo "run as root: it creates network namespaces" >&2
    exit 2
fi

server_ns=mirrust-syn-server-$$
client_ns=mirrust-syn-client-$$
server_ip=10.77.0.1
client_ip=10.77.0.2
port=8443
url=https://$server_ip:$port
linux_ua='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/160.0.0.0 Safari/537.36'
windows_ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/160.0.0.0 Safari/537.36'

work=$(mktemp -d)
log=$work/server.log
pid=

cleanup() {
    local status=$?
    if [[ -n $pid ]]; then
        # SIGINT is what the systemd unit sends; SIGKILL if the server has not gone in 10 s.
        kill -INT "$pid" 2>/dev/null || true
        for _ in $(seq 20); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.5
        done
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    if [[ $status -ne 0 && -s $log ]]; then
        echo "--- server output" >&2
        cat "$log" >&2
    fi
    # Deleting a namespace also deletes its end of the veth pair, and with it the other end.
    ip netns del "$server_ns" 2>/dev/null || true
    ip netns del "$client_ns" 2>/dev/null || true
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT

echo "--- network: $server_ns ($server_ip) <-veth-> $client_ns ($client_ip)"
ip netns add "$server_ns"
ip netns add "$client_ns"
# Created in place, so the interfaces never exist in the runner's own namespace.
ip link add mrs0 netns "$server_ns" type veth peer name mrc0 netns "$client_ns"
ip -n "$server_ns" addr add "$server_ip/24" dev mrs0
ip -n "$client_ns" addr add "$client_ip/24" dev mrc0
for ns in "$server_ns" "$client_ns"; do
    ip -n "$ns" link set lo up
done
ip -n "$server_ns" link set mrs0 up
ip -n "$client_ns" link set mrc0 up

echo "--- start $bin on $server_ip:$port"
# ip netns exec runs the binary in place of itself, so $! is the server's process.
ip netns exec "$server_ns" "$bin" --listen "$server_ip:$port" >"$log" 2>&1 &
pid=$!

# The server asks the kernel to keep SYNs right after it binds, so the SYN of this first
# request may come too early to be kept; the requests that are checked come after it.
ready=
for _ in $(seq 30); do
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "the server exited before it answered" >&2
        exit 1
    fi
    if ip netns exec "$client_ns" curl -sk --max-time 5 -o /dev/null "$url/api/clean"; then
        ready=1
        break
    fi
    sleep 1
done
if [[ -z $ready ]]; then
    echo "the server did not answer at $url within 30 tries" >&2
    exit 1
fi

# GET /api/all from the client namespace with User-Agent $1, into the file $2.
fetch() {
    ip netns exec "$client_ns" curl -sS -k --fail --max-time 10 -A "$1" -o "$2" "$url/api/all"
}
fetch "$linux_ua" "$work/linux.json"
fetch "$windows_ua" "$work/windows.json"

failed=0
# expect FILE DESCRIPTION JQ_FILTER: the filter must give true for the response in FILE.
expect() {
    if jq -e "$3" "$1" >/dev/null; then
        echo "ok: $2"
    else
        echo "FAILED: $2 ($(basename "$1"): $3)" >&2
        failed=1
    fi
}

for file in "$work/linux.json" "$work/windows.json"; do
    echo "--- $(basename "$file"): ip, tcpip.tcp_syn, tcpip.p0f"
    jq -c '{ip, tcp_syn: .tcpip.tcp_syn, p0f: .tcpip.p0f}' "$file"
    expect "$file" "ip is the client's address" \
        ".ip | startswith(\"$client_ip:\")"
    expect "$file" "tcpip.tcp_syn is present" \
        '.tcpip.tcp_syn | type == "object"'
    expect "$file" "the SYN is IPv4 from the client to the server" \
        ".tcpip.tcp_syn | .ip_version == 4 and .src_ip == \"$client_ip\" and .dst_ip == \"$server_ip\" and .dst_port == $port"
    expect "$file" "the SYN is the one of this connection (source port)" \
        '.tcpip.tcp_syn.src_port == (.ip | split(":") | .[1] | tonumber)'
    expect "$file" "TTL is that of a Linux sender one hop away (1..=64)" \
        '.tcpip.tcp_syn.ttl | type == "number" and . >= 1 and . <= 64'
    expect "$file" "MSS fits an Ethernet-size MTU (536..=1460)" \
        '.tcpip.tcp_syn.mss | type == "number" and . >= 536 and . <= 1460'
    expect "$file" "window is not zero" \
        '.tcpip.tcp_syn.window | type == "number" and . > 0'
    expect "$file" "TCP options are present and include mss" \
        '.tcpip.tcp_syn.options | type == "array" and length > 0 and any(. == "mss")'
    expect "$file" "the kernel kept headers only (payload_len 0)" \
        '.tcpip.tcp_syn.payload_len == 0'
    expect "$file" "p0f is an IPv4 signature" \
        '.tcpip.p0f | type == "string" and startswith("4:")'
    expect "$file" "tcp_mss is measured (not skip)" \
        '[.audit.checks[] | select(.id == "tcp_mss") | .status] | length == 1 and .[0] != "skip"'
done

echo "--- audit tcp_os"
jq -c '.audit.checks[] | select(.id == "tcp_os")' "$work/linux.json" "$work/windows.json"
expect "$work/linux.json" "tcp_os passes for a Linux User-Agent and names Linux" \
    '[.audit.checks[] | select(.id == "tcp_os")] | length == 1 and .[0].status == "pass" and (.[0].detail | contains("Linux"))'
expect "$work/windows.json" "tcp_os fails for a Windows User-Agent over a Linux SYN" \
    '[.audit.checks[] | select(.id == "tcp_os")] | length == 1 and .[0].status == "fail"'

if [[ $failed -ne 0 ]]; then
    echo "--- responses" >&2
    jq . "$work/linux.json" "$work/windows.json" >&2
    exit 1
fi
echo "--- ok: the SYN of a connection from $client_ip was captured and checked"
