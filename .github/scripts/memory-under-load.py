#!/usr/bin/env python3
"""Measures the resident memory of mirrust with every connection slot taken.

usage: python3 .github/scripts/memory-under-load.py <mirrust binary> [port]

For each scenario a fresh server is started with its default limit of 1024 connections, 1024
connections are opened and held, and the server's RSS is sampled with ps until they are
closed. The connection deadline is 15 seconds, so everything happens inside that. Only TCP is
exercised: no QUIC connection is made.

The numbers behind MemoryMax= in deploy/mirrust.service come from this script; see "Bounded
number of clients" in docs/architecture.md. It is run by hand, not by CI. Python 3.8 or later,
standard library only; the port (default 18477) must be free on 127.0.0.1.
"""
import resource
import socket
import ssl
import subprocess
import sys
import threading
import time

BINARY = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 18477
ADDR = ("127.0.0.1", PORT)
SLOTS = 1024
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(kind, flags, stream, payload):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


def tcp():
    s = socket.create_connection(ADDR, timeout=10)
    return s


def idle():
    """A TCP connection that sends nothing."""
    return tcp()


def half_open_tls():
    """A ClientHello that claims 65,000 bytes, of which 60,000 arrive: the server keeps them."""
    s = tcp()
    message = b"\x01" + (65000).to_bytes(3, "big") + bytes(60000 - 4)
    out = b""
    for at in range(0, len(message), 16384):
        chunk = message[at:at + 16384]
        out += b"\x16\x03\x01" + len(chunk).to_bytes(2, "big") + chunk
    s.sendall(out)
    return s


def tls(alpn):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols([alpn])
    s = context.wrap_socket(tcp(), server_hostname="localhost")
    assert s.selected_alpn_protocol() == alpn, s.selected_alpn_protocol()
    return s


def h2_holding_input():
    """An HTTP/2 request that never ends: POST headers and 62 KB of DATA, under the 64 KiB cap."""
    s = tls("h2")
    out = PREFACE + frame(0x4, 0, 0, b"") + frame(0x1, 0x4, 1, b"\x83\x87\x84")
    for size in (16384, 16384, 16384, 13000):
        out += frame(0x0, 0, 1, bytes(size))
    assert len(out) < 65536
    s.sendall(out)
    return s


def h2_large_report_zero_window():
    """A finished HTTP/2 request with 60 KB of decoded headers and a zero window: the server
    builds the report, which lists them, and holds it until the window opens."""
    s = tls("h2")
    value = b"v" * 4000
    # GET, https, :path /api/all, one 4,000-byte header put in the dynamic table and 14
    # references to it.
    block = b"\x82\x87\x04\x08/api/all" + b"\x40\x01x\x7f\xa1\x1e" + value + b"\xbe" * 14
    out = PREFACE + frame(0x4, 0, 0, b"\x00\x04\x00\x00\x00\x00") + frame(0x1, 0x5, 1, block)
    s.sendall(out)
    return s


def http1_partial_head():
    """An HTTP/1.1 request head of 16,000 bytes that never ends."""
    s = tls("http/1.1")
    s.sendall(b"GET / HTTP/1.1\r\nCookie: " + b"c" * 15976)
    return s


def rss_kib(pid):
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout
    return int(out.strip() or 0)


def run(name, makers):
    server = subprocess.Popen(
        [BINARY, "--listen", f"127.0.0.1:{PORT}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            try:
                socket.create_connection(ADDR, timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        time.sleep(1.0)
        before = rss_kib(server.pid)
        peak = [before]
        stop = threading.Event()

        def sample():
            while not stop.is_set():
                peak[0] = max(peak[0], rss_kib(server.pid))
                time.sleep(0.1)

        sampler = threading.Thread(target=sample)
        sampler.start()
        started = time.time()
        held = []
        failed = 0
        for index in range(SLOTS):
            try:
                held.append(makers[index % len(makers)]())
            except OSError:
                failed += 1
        opened = time.time() - started
        time.sleep(max(0.0, min(3.0, 12.0 - opened)))
        stop.set()
        sampler.join()
        at_hold = rss_kib(server.pid)
        for s in held:
            try:
                s.close()
            except OSError:
                pass
        time.sleep(1.5)
        after = rss_kib(server.pid)
        print(f"{name:34} held {len(held):4} (failed {failed:3}) in {opened:4.1f}s  "
              f"before {before / 1024:6.1f} MiB  peak {max(peak[0], at_hold) / 1024:6.1f} MiB  "
              f"after close {after / 1024:6.1f} MiB", flush=True)
    finally:
        server.terminate()
        try:
            _, err = server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            _, err = server.communicate()
        refused = [line for line in err.splitlines() if "refused" in line]
        if refused:
            print("   server:", refused[-1])


soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
want = 8192 if hard == resource.RLIM_INFINITY else min(8192, hard)
resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))

run("idle TCP", [idle])
run("half-open TLS, 60 KB ClientHello", [half_open_tls])
run("TLS, HTTP/1.1 head of 16 KB", [http1_partial_head])
run("TLS, HTTP/2 holding 62 KB", [h2_holding_input])
run("TLS, HTTP/2 report held, 0 window", [h2_large_report_zero_window])
run("a quarter of each", [idle, half_open_tls, http1_partial_head, h2_holding_input])
