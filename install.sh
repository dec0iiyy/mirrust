#!/bin/sh
# install.sh: download the mirrust release binary for this system, check it against the
# release's SHA256SUMS and install it.
#
#   curl -fsSL https://github.com/dec0iiyy/mirrust/releases/latest/download/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version v0.2.0 --prefix "$HOME/.local/bin"
#
# Options (each has an environment variable with the same effect; the option wins):
#   --version vX.Y.Z   release to install (MIRRUST_VERSION; default: the latest release)
#   --prefix DIR       directory for the mirrust binary (MIRRUST_PREFIX; default /usr/local/bin)
#   -h, --help         print this text
#
# MIRRUST_BASE_URL and MIRRUST_DEFAULT_PREFIX exist for the tests in
# .github/scripts/test-install.sh. The first replaces the release URL, the second the default
# of --prefix. Do not set them otherwise.
#
# What it does, in order: detect the system with uname; download the binary and SHA256SUMS
# into a temporary directory that is removed on exit; verify the checksum, and stop without
# installing anything if it does not match; run `gh attestation verify` if gh is installed,
# and report the result (a missing or failing gh never blocks the install); install the
# binary with mode 0755. If the directory is not writable it uses sudo for that last step
# only, and if there is no sudo either and --prefix was not given it installs into
# $HOME/.local/bin. It never needs root otherwise.
#
# The checksum file comes from the same place as the binary, so the check catches a damaged
# or truncated download, not a compromised release. The attestation, signed by this
# repository's release workflow, is the check that does: `gh attestation verify FILE --repo
# dec0iiyy/mirrust`.
#
# Everything is inside functions and `main "$@"` is the last line: a download cut short
# runs nothing.

set -eu

REPO=dec0iiyy/mirrust
RELEASES_PAGE=https://github.com/$REPO/releases

say() {
    printf '%s\n' "mirrust install: $*"
}

warn() {
    printf '%s\n' "mirrust install: $*" >&2
}

die() {
    printf '%s\n' "mirrust install: error: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
usage: install.sh [--version vX.Y.Z] [--prefix DIR]

Downloads the mirrust release binary for this system, verifies it against the release's
SHA256SUMS and installs it as DIR/mirrust (default /usr/local/bin, with sudo for the install
step if that directory is not writable).

  --version vX.Y.Z   release to install (default: the latest); also MIRRUST_VERSION
  --prefix DIR       install directory; also MIRRUST_PREFIX
  -h, --help         print this text

Linux (x86_64, aarch64) and macOS (arm64, x86_64). Other systems: see
https://github.com/dec0iiyy/mirrust/releases
EOF
}

# Removes the temporary directory; runs on every way out of the script.
cleanup() {
    if [ -n "${tmp:-}" ] && [ -d "$tmp" ]; then
        rm -rf "$tmp"
    fi
}

have() {
    command -v "$1" >/dev/null 2>&1
}

# Sets $os and $asset from uname, or stops with a pointer to the Releases page.
detect_system() {
    kernel=$(uname -s)
    machine=$(uname -m)
    case "$kernel" in
        Linux)
            os=linux
            case "$machine" in
                x86_64 | amd64) arch=x86_64 ;;
                aarch64 | arm64) arch=aarch64 ;;
                *) unsupported "Linux on $machine" ;;
            esac
            ;;
        Darwin)
            os=macos
            case "$machine" in
                arm64 | aarch64) arch=arm64 ;;
                x86_64) arch=x86_64 ;;
                *) unsupported "macOS on $machine" ;;
            esac
            ;;
        MINGW* | MSYS* | CYGWIN* | Windows_NT)
            unsupported "Windows (download mirrust-windows-x86_64.exe from the Releases page)"
            ;;
        *) unsupported "$kernel on $machine" ;;
    esac
    asset=mirrust-$os-$arch
}

unsupported() {
    die "this installer does not support $1. Releases and instructions: $RELEASES_PAGE"
}

# Sets $downloader to curl, or wget when there is no curl.
pick_downloader() {
    if have curl; then
        downloader=curl
    elif have wget; then
        downloader=wget
    else
        die "neither curl nor wget is installed; install one of them and run this again"
    fi
}

# fetch URL FILE
fetch() {
    if [ "$downloader" = curl ]; then
        curl --fail --silent --show-error --location --retry 2 --output "$2" "$1"
    else
        wget --quiet --output-document="$2" "$1"
    fi
}

# Prints the SHA-256 of a file, in lowercase hex.
sha256_of() {
    if have sha256sum; then
        sha256sum "$1" | awk '{ print $1 }'
    elif have shasum; then
        shasum -a 256 "$1" | awk '{ print $1 }'
    else
        die "neither sha256sum nor shasum is installed, so the download cannot be verified"
    fi
}

# Stops unless $tmp/$asset is the file that $tmp/SHA256SUMS lists under that name.
verify_checksum() {
    # Lowercase, as sha256_of prints it: the check below accepts upper-case hex digits, and a
    # SHA256SUMS written with them must not be reported as a mismatch.
    expected=$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1 }' "$tmp/SHA256SUMS" |
        tr 'A-F' 'a-f')
    case "$expected" in
        "") die "SHA256SUMS has no entry for $asset; nothing was installed" ;;
        *[!0-9a-fA-F]* | *"
"*) die "SHA256SUMS has an unusable entry for $asset; nothing was installed" ;;
    esac
    actual=$(sha256_of "$tmp/$asset")
    if [ "$actual" != "$expected" ]; then
        {
            printf '%s\n' "mirrust install: ERROR: CHECKSUM MISMATCH for $asset"
            printf '%s\n' "  expected (SHA256SUMS): $expected"
            printf '%s\n' "  downloaded file:       $actual"
            printf '%s\n' "The download is damaged or has been tampered with. Nothing was installed and"
            printf '%s\n' "the downloaded files are deleted. Try again; if it keeps failing, report it at"
            printf '%s\n' "$RELEASES_PAGE"
        } >&2
        exit 1
    fi
    say "checksum ok: $asset matches SHA256SUMS"
}

# Reports the result of gh attestation verify. Never stops the install.
check_attestation() {
    if [ -n "${MIRRUST_BASE_URL:-}" ]; then
        say "note: attestation not checked, because MIRRUST_BASE_URL replaces the release URL"
    elif ! have gh; then
        say "note: gh is not installed, so the build provenance was not checked (gh attestation verify $asset --repo $REPO)"
    elif gh attestation verify "$tmp/$asset" --repo "$REPO" >/dev/null 2>&1; then
        say "attestation ok: gh attestation verify confirms that $REPO's release workflow built this file"
    else
        say "note: gh attestation verify did not succeed (not signed in, offline, or a release without provenance); the checksum matched, so continuing"
    fi
}

# Whether the directory, or the nearest existing directory above it, is writable by us.
can_write() {
    dir=$1
    while [ ! -d "$dir" ]; do
        parent=$(dirname -- "$dir")
        if [ "$parent" = "$dir" ]; then
            return 1
        fi
        dir=$parent
    done
    [ -w "$dir" ]
}

# Sets $dest_dir, $use_sudo (yes or no) and $fallback (yes when $HOME/.local/bin was chosen).
choose_destination() {
    dest_dir=$prefix
    use_sudo=no
    fallback=no
    if can_write "$dest_dir"; then
        return 0
    fi
    if have sudo; then
        use_sudo=yes
        say "$dest_dir is not writable by you: using sudo for the install step only (it may ask for your password)"
        return 0
    fi
    if [ "$prefix_given" = yes ]; then
        die "$dest_dir is not writable and sudo is not installed; give another --prefix, or run as a user that can write there"
    fi
    if [ -z "${HOME:-}" ]; then
        die "$dest_dir is not writable, sudo is not installed and HOME is not set"
    fi
    dest_dir=$HOME/.local/bin
    fallback=yes
    say "$prefix is not writable and sudo is not installed: installing into $dest_dir instead"
}

# Installs $tmp/$asset as $dest_dir/mirrust, mode 0755.
install_binary() {
    # Each command returns on failure: the caller runs this in a `||`, where `set -e` is off.
    # `install -d -m` also changes the mode of a directory that already exists (BSD install does,
    # and so does GNU install), so a directory is only created when it is missing. `--` keeps a
    # --prefix that starts with a hyphen from being read as an option.
    if [ "$use_sudo" = yes ]; then
        if [ ! -d "$dest_dir" ]; then
            sudo install -d -m 0755 -- "$dest_dir" || return 1
        fi
        sudo install -m 0755 -- "$tmp/$asset" "$dest_dir/mirrust" || return 1
    else
        if [ ! -d "$dest_dir" ]; then
            install -d -m 0755 -- "$dest_dir" || return 1
        fi
        install -m 0755 -- "$tmp/$asset" "$dest_dir/mirrust" || return 1
    fi
}

on_path() {
    case ":$PATH:" in
        *":$1:"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Prints what to do next. $cmd is how to call the binary from here.
next_steps() {
    if on_path "$dest_dir"; then
        cmd=mirrust
    else
        cmd=$dest_dir/mirrust
    fi
    printf '\n'
    say "installed $version as $dest_dir/mirrust"
    if [ "$fallback" = yes ] && ! on_path "$dest_dir"; then
        say "$dest_dir is not in your PATH. Add it, for example:"
        printf '%s\n' "    export PATH=\"$dest_dir:\$PATH\""
    fi
    printf '\n'
    if [ "$os" = linux ]; then
        printf '%s\n' "Next steps"
        printf '%s\n' "  A server with a DNS A record for your host name (Linux with systemd):"
        printf '%s\n' "    sudo $cmd install --domain your.host"
        printf '%s\n' "  It sets mirrust up as a service on TCP and UDP port 443 with a Let's Encrypt"
        printf '%s\n' "  certificate (--domain accepts its Subscriber Agreement,"
        printf '%s\n' "  https://letsencrypt.org/repository/). Without systemd, run it directly:"
        printf '%s\n' "    sudo $cmd --domain your.host"
        printf '%s\n' "  A quick look on this machine:"
    else
        printf '%s\n' "A quick look on this machine:"
    fi
    printf '%s\n' "    $cmd"
    printf '%s\n' "  then open https://localhost:8443 in a browser (the certificate is self-signed;"
    printf '%s\n' "  with curl, add -k)."
}

main() {
    version=${MIRRUST_VERSION:-latest}
    prefix=
    prefix_given=no
    if [ -n "${MIRRUST_PREFIX:-}" ]; then
        prefix=$MIRRUST_PREFIX
        prefix_given=yes
    fi
    while [ $# -gt 0 ]; do
        case "$1" in
            -h | --help)
                usage
                exit 0
                ;;
            --version | --prefix)
                [ $# -ge 2 ] || die "$1 needs a value (see --help)"
                if [ "$1" = --version ]; then
                    version=$2
                else
                    prefix=$2
                    prefix_given=yes
                fi
                shift 2
                ;;
            --version=*)
                version=${1#--version=}
                shift
                ;;
            --prefix=*)
                prefix=${1#--prefix=}
                prefix_given=yes
                shift
                ;;
            *) die "unknown option $1 (see --help)" ;;
        esac
    done
    if [ -z "$prefix" ]; then
        if [ "$prefix_given" = yes ]; then
            die "--prefix needs a directory, not an empty value"
        fi
        prefix=${MIRRUST_DEFAULT_PREFIX:-/usr/local/bin}
    fi

    # A tag is v plus a version: letters, digits, dots and hyphens, nothing a URL would read
    # differently. "0.2.0" is accepted for "v0.2.0".
    case "$version" in
        latest) ;;
        v*) ;;
        [0-9]*) version=v$version ;;
        *) die "bad --version $version: expected vX.Y.Z, for example v0.2.0" ;;
    esac
    case "$version" in
        *[!A-Za-z0-9._-]*) die "bad --version $version: expected vX.Y.Z, for example v0.2.0" ;;
    esac

    detect_system
    pick_downloader
    if [ -n "${MIRRUST_BASE_URL:-}" ]; then
        base_url=${MIRRUST_BASE_URL%/}
    elif [ "$version" = latest ]; then
        base_url=$RELEASES_PAGE/latest/download
    else
        base_url=$RELEASES_PAGE/download/$version
    fi
    choose_destination

    say "installing mirrust ($version) for $os $arch"
    say "  from $base_url/$asset (checked against SHA256SUMS)"
    say "  to   $dest_dir/mirrust"

    tmp=$(mktemp -d 2>/dev/null || mktemp -d -t mirrust) || die "cannot create a temporary directory"
    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    fetch "$base_url/$asset" "$tmp/$asset" ||
        die "downloading $base_url/$asset failed (does the release exist? see $RELEASES_PAGE)"
    fetch "$base_url/SHA256SUMS" "$tmp/SHA256SUMS" ||
        die "downloading $base_url/SHA256SUMS failed"
    verify_checksum
    check_attestation
    install_binary || die "installing into $dest_dir failed"

    # A file that does not run here (the wrong architecture, say) should not pass in silence.
    if ! "$dest_dir/mirrust" --help >/dev/null 2>&1; then
        warn "warning: $dest_dir/mirrust was installed but does not run on this system"
    fi
    next_steps
}

main "$@"
