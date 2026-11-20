#!/bin/sh
# Runs smoke-test.sh for a Linux binary inside clean containers, one per image.
#
#   smoke-test-linux.sh BINARY [IMAGE...]
#
# The default images are debian:12-slim (glibc) and alpine (musl). The binary is mounted
# read-only, so what runs is exactly the file that CI goes on to package. Needs Docker, and
# a binary built for the architecture of the Docker host.
set -eu

bin=${1:?usage: smoke-test-linux.sh BINARY [IMAGE...]}
shift
[ "$#" -gt 0 ] || set -- debian:12-slim alpine:3

here=$(cd "$(dirname "$0")" && pwd)
bin=$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")

for image in "$@"; do
    echo "::group::smoke test in $image"
    timeout 300 docker run --rm \
        --volume "$bin:/usr/local/bin/mirrust:ro" \
        --volume "$here/smoke-test.sh:/smoke-test.sh:ro" \
        "$image" sh /smoke-test.sh /usr/local/bin/mirrust
    echo "::endgroup::"
done
