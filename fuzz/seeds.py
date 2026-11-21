#!/usr/bin/env python3
"""Writes the seed corpora under fuzz/corpus/ from corpus/*.jsonl and the QUIC test fixtures.

Run from the repository root: python3 fuzz/seeds.py
The output is committed; run it again after a change to the inputs or to the input framing.
"""

import base64
import json
import re
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fuzz" / "corpus"
QUIC_DATA = ROOT / "crates" / "quic" / "tests" / "data"

# Keeps the committed seeds to a few hundred KB.
MAX_HELLOS = 40
MAX_MALFORMED = 60
MAX_MALFORMED_LEN = 2048
MAX_SYNS = 80


def lines(name):
    with open(ROOT / "corpus" / name) as f:
        return [json.loads(line) for line in f if line.strip()]


def write(target, name, data):
    path = OUT / target / (re.sub(r"[^A-Za-z0-9._-]+", "_", name) + ".bin")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def framed(chunks):
    """The framing of mirrust_fuzz::split_chunks: each chunk after a big-endian u16 length."""
    return b"".join(struct.pack(">H", len(c)) + c for c in chunks)


def varint(value):
    if value < 0x40:
        return bytes([value])
    return struct.pack(">H", 0x4000 | value)


def crypto_frame(offset, data):
    return b"\x06" + varint(offset) + varint(len(data)) + data


def main():
    shutil.rmtree(OUT, ignore_errors=True)

    for case in lines("hellos.jsonl")[:MAX_HELLOS]:
        write("client_hello", case["name"], bytes.fromhex(case["hex"]))
    malformed = [c for c in lines("malformed.jsonl") if len(c["hex"]) <= 2 * MAX_MALFORMED_LEN]
    for case in malformed[:MAX_MALFORMED]:
        write("client_hello", "malformed-" + case["name"], bytes.fromhex(case["hex"]))

    # The first byte sets the chunk size: 0x0f feeds the stream 16 bytes at a time.
    for case in lines("h2.jsonl"):
        write("http2_frames", case["name"], b"\x0f" + base64.b64decode(case["b64"]))

    for case in lines("syn.jsonl")[:MAX_SYNS]:
        write("tcp_syn", case["name"], bytes.fromhex(case["hex"]))

    chrome = [bytes.fromhex(l) for l in (QUIC_DATA / "chrome160_datagrams.hex").read_text().split()]
    rfc_packet = bytes.fromhex((QUIC_DATA / "rfc9001_a2_protected_packet.hex").read_text().strip())
    write("quic_datagrams", "chrome160", framed(chrome))
    write("quic_datagrams", "chrome160-reversed", framed(chrome[::-1]))
    write("quic_datagrams", "rfc9001-a2", framed([rfc_packet]))

    rfc_frame = bytes.fromhex((QUIC_DATA / "rfc9001_a2_crypto_frame.hex").read_text().strip())
    hello = bytes.fromhex((QUIC_DATA / "chrome160_client_hello.hex").read_text().strip())
    half = len(hello) // 2
    write("quic_crypto", "rfc9001-a2-v1", b"\x00" + framed([rfc_frame]))
    write("quic_crypto", "rfc9001-a2-v2", b"\x01" + framed([rfc_frame]))
    write(
        "quic_crypto",
        "chrome160-reordered",
        b"\x00" + framed([crypto_frame(half, hello[half:]), crypto_frame(0, hello[:half])]),
    )
    # PADDING and PING around the frame, and a repeated copy of the first half.
    write(
        "quic_crypto",
        "chrome160-padding-ping-repeat",
        b"\x00"
        + framed(
            [
                b"\x00\x00\x01" + crypto_frame(0, hello[:half]),
                crypto_frame(0, hello[:half]) + crypto_frame(half, hello[half:]) + b"\x00" * 8,
            ]
        ),
    )


if __name__ == "__main__":
    main()
