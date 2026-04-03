#!/bin/sh
set -eu

REPO="ags-slc/s2"

# Install location: override with INSTALL_DIR, or pass --user for ~/.local/bin
if [ -n "${INSTALL_DIR:-}" ]; then
  : # user override, keep it
elif [ "${1:-}" = "--user" ]; then
  INSTALL_DIR="$HOME/.local/bin"
else
  INSTALL_DIR="/usr/local/bin"
fi

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64)  TARGET="aarch64-apple-darwin" ;;
      x86_64) TARGET="x86_64-apple-darwin" ;;
      *)      echo "Error: unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
    SHA_CMD="shasum -a 256"
    ;;
  Linux)
    case "$ARCH" in
      x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
      aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
      *)       echo "Error: unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
    SHA_CMD="sha256sum"
    ;;
  *)
    echo "Error: unsupported OS: $OS" >&2
    exit 1
    ;;
esac

# Resolve version
if [ -z "${VERSION:-}" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\(.*\)".*/\1/p')"
  if [ -z "$VERSION" ]; then
    echo "Error: could not determine latest version" >&2
    exit 1
  fi
fi

TARBALL="s2-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading s2 ${VERSION} for ${TARGET}..."
curl -fsSL -o "${TMPDIR}/${TARBALL}" "$URL"
curl -fsSL -o "${TMPDIR}/checksums.txt" "$CHECKSUMS_URL"

# Verify checksum
echo "Verifying checksum..."
cd "$TMPDIR"
EXPECTED="$(grep "$TARBALL" checksums.txt | awk '{print $1}')"
ACTUAL="$($SHA_CMD "$TARBALL" | awk '{print $1}')"
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Error: checksum mismatch" >&2
  echo "  expected: $EXPECTED" >&2
  echo "  actual:   $ACTUAL" >&2
  exit 1
fi

# Extract and install
tar xzf "$TARBALL"

# Try direct install first; fall back to sudo if it fails
# ([ -w ] is unreliable on macOS due to SIP)
if install -m 755 s2 "$INSTALL_DIR/s2" 2>/dev/null; then
  :
else
  echo "Installing to ${INSTALL_DIR} requires sudo..."
  sudo install -d "$INSTALL_DIR"
  sudo install -m 755 s2 "$INSTALL_DIR/s2"
fi

echo "Installed s2 ${VERSION} to ${INSTALL_DIR}/s2"
