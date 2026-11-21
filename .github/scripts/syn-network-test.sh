#!/usr/bin/env bash
# Checks the TCP SYN capture over a connection between two different addresses, over IPv4
# and over IPv6.
#
#   sudo syn-network-test.sh BINARY
#
# The tests in crates/server/tests/ read the SYN of a loopback connection. This one puts the
# server and the client in two network namespaces joined by a veth pair, server on 10.77.0.1
# and fd77::1, client (curl) on 10.77.0.2 and fd77::2, so the SYN is a real one from the
# client's network stack, sent over an interface. It runs three cases, each with its own
# server process:
#
#   ipv4       --listen 10.77.0.1:8443, curl to 10.77.0.1
#   ipv6       --listen [fd77::1]:8443, curl to [fd77::1]
#   dualstack  --listen [::]:8443, curl to 10.77.0.1: an IPv4 client of an IPv6 socket
#
# and checks in each the `ip` field, the `tcpip` fields and the audit checks `tcp_os` and
# `tcp_mss`, including that a Linux client claiming a Windows User-Agent fails `tcp_os`.
# HTTP/3 is not checked: the curl of the Ubuntu runner is built without it.
#
# Linux only, as root (it creates namespaces), with ip (iproute2), curl and jq. It builds
# nothing: BINARY is a mirrust built for this machine. It leaves no namespace or process
# behind, also when it fails, and prints the server output of a case that failed.
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
server_ip4=10.77.0.1
client_ip4=10.77.0.2
# Unique local addresses (RFC 4193), never routed outside the veth pair.
server_ip6=fd77::1
client_ip6=fd77::2
port=8443
linux_ua='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/160.0.0.0 Safari/537.36'
windows_ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/160.0.0.0 Safari/537.36'

work=$(mktemp -d)
log=
pid=
failed=0

# Stops the server of the current case, if one runs.
stop_server() {
    if [[ -n $pid ]]; then
        # SIGINT is what the systemd unit sends; SIGKILL if the server has not gone in 10 s.
        kill -INT "$pid" 2>/dev/null || true
        for _ in $(seq 20); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.5
        done
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        pid=
    fi
}

cleanup() {
    local status=$?
    stop_server
    if [[ $status -ne 0 && -n $log && -s $log ]]; then
        echo "--- server output ($(basename "$log"))" >&2
        cat "$log" >&2
    fi
    # Deleting a namespace also deletes its end of the veth pair, and with it the other end.
    ip netns del "$server_ns" 2>/dev/null || true
    ip netns del "$client_ns" 2>/dev/null || true
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT

echo "--- network: $server_ns ($server_ip4, $server_ip6) <-veth-> $client_ns ($client_ip4, $client_ip6)"
ip netns add "$server_ns"
ip netns add "$client_ns"
# Created in place, so the interfaces never exist in the runner's own namespace.
ip link add mrs0 netns "$server_ns" type veth peer name mrc0 netns "$client_ns"
for ns in "$server_ns" "$client_ns"; do
    # A new namespace may start with IPv6 off, depending on the host's sysctl defaults.
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
done
ip -n "$server_ns" addr add "$server_ip4/24" dev mrs0
ip -n "$client_ns" addr add "$client_ip4/24" dev mrc0
# nodad: no duplicate address detection, so the addresses are usable as soon as the link is up.
ip -n "$server_ns" -6 addr add "$server_ip6/64" dev mrs0 nodad
ip -n "$client_ns" -6 addr add "$client_ip6/64" dev mrc0 nodad
for ns in "$server_ns" "$client_ns"; do
    ip -n "$ns" link set lo up
done
ip -n "$server_ns" link set mrs0 up
ip -n "$client_ns" link set mrc0 up

# Even with nodad, wait until neither end has a tentative IPv6 address (at most 10 s).
for _ in $(seq 20); do
    tentative=$(ip -n "$server_ns" -6 addr show dev mrs0 tentative)$(ip -n "$client_ns" -6 addr show dev mrc0 tentative)
    [[ -z $tentative ]] && break
    sleep 0.5
done
if [[ -n $tentative ]]; then
    echo "IPv6 addresses are still tentative:" >&2
    echo "$tentative" >&2
    exit 1
fi
ip -n "$server_ns" addr show dev mrs0
ip -n "$client_ns" addr show dev mrc0

# expect FILE DESCRIPTION JQ_FILTER: the filter must give true for the response in FILE.
expect() {
    if jq -e "$3" "$1" >/dev/null; then
        echo "ok: $2"
    else
        echo "FAILED: $2 ($(basename "$1"): $3)" >&2
        failed=$((failed + 1))
    fi
}

# run_case NAME LISTEN URL CURL_FAMILY CLIENT_IP SHOWN_CLIENT SERVER_IP VERSION MSS_MIN MSS_MAX
#
# Starts the server on LISTEN, fetches URL/api/all from the client namespace with curl
# CURL_FAMILY (-4 or -6) under a Linux and a Windows User-Agent, and checks the answers:
# `ip` is SHOWN_CLIENT:port, the SYN is an IPv<VERSION> packet from CLIENT_IP to SERVER_IP
# with an MSS in MSS_MIN..=MSS_MAX. IPv6 addresses are given without brackets.
run_case() {
    local name=$1 listen=$2 url=$3 family=$4 client_ip=$5 shown=$6 server_ip=$7 version=$8
    local mss_min=$9 mss_max=${10}
    local linux=$work/$name-linux.json windows=$work/$name-windows.json
    local failed_before=$failed

    echo
    echo "=== $name: --listen $listen, curl $family $url"
    log=$work/$name-server.log
    # ip netns exec runs the binary in place of itself, so $! is the server's process.
    ip netns exec "$server_ns" "$bin" --listen "$listen" >"$log" 2>&1 &
    pid=$!

    # The server asks the kernel to keep SYNs right after it binds, so the SYN of this first
    # request may come too early to be kept; the requests that are checked come after it.
    local ready=
    for _ in $(seq 30); do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "the server exited before it answered" >&2
            exit 1
        fi
        if ip netns exec "$client_ns" curl "$family" -g -sk --max-time 5 -o /dev/null "$url/api/clean"; then
            ready=1
            break
        fi
        sleep 1
    done
    if [[ -z $ready ]]; then
        echo "the server did not answer at $url within 30 tries" >&2
        exit 1
    fi

    ip netns exec "$client_ns" curl "$family" -g -sS -k --fail --max-time 10 -A "$linux_ua" -o "$linux" "$url/api/all"
    ip netns exec "$client_ns" curl "$family" -g -sS -k --fail --max-time 10 -A "$windows_ua" -o "$windows" "$url/api/all"

    local file
    for file in "$linux" "$windows"; do
        echo "--- $(basename "$file"): ip, tcpip, audit tcp_os and tcp_mss"
        jq -c '{ip, tcp_syn: .tcpip.tcp_syn, p0f: .tcpip.p0f}' "$file"
        jq -c '.audit.checks[]? | select(.id == "tcp_os" or .id == "tcp_mss")' "$file"
        expect "$file" "ip is the client's address, $shown" \
            ".ip | startswith(\"$shown:\")"
        expect "$file" "tcpip.tcp_syn is present" \
            '.tcpip.tcp_syn | type == "object"'
        expect "$file" "the SYN is IPv$version from the client to the server" \
            ".tcpip.tcp_syn | .ip_version == $version and .src_ip == \"$client_ip\" and .dst_ip == \"$server_ip\" and .dst_port == $port"
        expect "$file" "the SYN is the one of this connection (source port)" \
            '.tcpip.tcp_syn.src_port == (.ip | split(":") | last | tonumber)'
        expect "$file" "TTL (IPv6: hop limit) is that of a Linux sender one hop away (1..=64)" \
            '.tcpip.tcp_syn.ttl | type == "number" and . >= 1 and . <= 64'
        expect "$file" "MSS fits an Ethernet-size MTU ($mss_min..=$mss_max)" \
            ".tcpip.tcp_syn.mss | type == \"number\" and . >= $mss_min and . <= $mss_max"
        expect "$file" "window is not zero" \
            '.tcpip.tcp_syn.window | type == "number" and . > 0'
        expect "$file" "TCP options are present and include mss" \
            '.tcpip.tcp_syn.options | type == "array" and length > 0 and any(. == "mss")'
        expect "$file" "the kernel kept headers only (payload_len 0)" \
            '.tcpip.tcp_syn.payload_len == 0'
        expect "$file" "p0f is an IPv$version signature" \
            ".tcpip.p0f | type == \"string\" and startswith(\"$version:\")"
        expect "$file" "tcp_mss is measured (not skip)" \
            '[.audit.checks[] | select(.id == "tcp_mss") | .status] | length == 1 and .[0] != "skip"'
    done
    expect "$linux" "tcp_os passes for a Linux User-Agent and names Linux" \
        '[.audit.checks[] | select(.id == "tcp_os")] | length == 1 and .[0].status == "pass" and (.[0].detail | contains("Linux"))'
    expect "$windows" "tcp_os fails for a Windows User-Agent over a Linux SYN" \
        '[.audit.checks[] | select(.id == "tcp_os")] | length == 1 and .[0].status == "fail"'

    stop_server
    if [[ $failed -ne $failed_before ]]; then
        echo "--- $name: server output" >&2
        cat "$log" >&2
    fi
}

# IPv4: MSS 1460 on Ethernet; 536 is the IPv4 default when no MSS is negotiated.
run_case ipv4 "$server_ip4:$port" "https://$server_ip4:$port" -4 \
    "$client_ip4" "$client_ip4" "$server_ip4" 4 536 1460
# IPv6: MSS 1440 on Ethernet; 1220 is what the IPv6 minimum MTU of 1280 leaves.
run_case ipv6 "[$server_ip6]:$port" "https://[$server_ip6]:$port" -6 \
    "$client_ip6" "[$client_ip6]" "$server_ip6" 6 1220 1440
# The kernel keeps the SYN of an IPv4 client as it came, an IPv4 packet, and the server shows
# the client's IPv4-mapped address (::ffff:10.77.0.2) as plain IPv4.
run_case dualstack "[::]:$port" "https://$server_ip4:$port" -4 \
    "$client_ip4" "$client_ip4" "$server_ip4" 4 536 1460
log=

if [[ $failed -ne 0 ]]; then
    echo "--- $failed checks failed; responses" >&2
    for file in "$work"/*.json; do
        echo "--- $(basename "$file")" >&2
        jq . "$file" >&2
    done
    exit 1
fi
echo "--- ok: the SYNs of connections from $client_ip4 and $client_ip6 were captured and checked"
