#!/usr/bin/env bash
set -eo pipefail

# gsearch installer bootstrap
# Downloads gsearch-server + gsearch-installer binaries,
# then runs the interactive installer (TUI with OAuth, project setup, wiring).

REPO="daanielcruz/gsearch-mcp"
INSTALL_DIR="$HOME/.gsearch"

R='\033[0m' B='\033[1m' G='\033[32m' Y='\033[33m' D='\033[2m' RED='\033[31m'

info()  { printf "  ${G}>${R} %s\n" "$1"; }
warn()  { printf "  ${Y}>${R} %s\n" "$1"; }
fail()  { printf "  ${RED}>${R} %s\n" "$1"; exit 1; }

detect_platform() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$os" in
        darwin)  os="darwin" ;;
        linux)   os="linux" ;;
        mingw*|msys*|cygwin*) os="windows" ;;
        *) fail "unsupported OS: $os" ;;
    esac

    case "$arch" in
        x86_64|amd64)  arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        *) fail "unsupported architecture: $arch" ;;
    esac

    PLATFORM="${os}-${arch}"
    SUFFIX=""
    if [ "$os" = "windows" ]; then
        SUFFIX=".exe"
    fi
}

get_latest_version() {
    VERSION=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name"' | head -1 | cut -d'"' -f4) || true
    if [ -z "${VERSION:-}" ]; then
        fail "could not determine latest version — is the repo public?"
    fi
}

download_binary() {
    local name="$1"
    local dest="$2"
    local url="https://github.com/${REPO}/releases/download/${VERSION}/${name}-${PLATFORM}${SUFFIX}"

    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$dest" || fail "download failed: ${name}-${PLATFORM}${SUFFIX}"
    elif command -v wget &>/dev/null; then
        wget -qO "$dest" "$url" || fail "download failed: ${name}-${PLATFORM}${SUFFIX}"
    else
        fail "curl or wget required"
    fi

    chmod +x "$dest"

}

main() {
    printf "\n  ${B}gsearch${R} ${D}installer${R}\n\n"

    detect_platform
    get_latest_version

    local tmpdir
    tmpdir="$(mktemp -d)"

    # download both binaries to same tmpdir (installer looks for server next to itself)
    info "downloading gsearch ${VERSION} for ${PLATFORM}..."
    download_binary "gsearch-server" "${tmpdir}/gsearch-server${SUFFIX}"
    download_binary "gsearch-installer" "${tmpdir}/gsearch-installer${SUFFIX}"

    printf "\n"

    # run the interactive installer (TUI with OAuth, project setup, wiring)
    "${tmpdir}/gsearch-installer${SUFFIX}"
    local exit_code=$?

    # cleanup
    rm -rf "$tmpdir"

    exit $exit_code
}

main "$@"
