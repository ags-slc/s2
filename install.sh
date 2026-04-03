#!/bin/sh
set -eu

REPO="ags-slc/s2"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS
OS="$(uname -s)"
if [ "$OS" != "Darwin" ]; then
  echo "Error: s2 currently only supports macOS (detected: $OS)" >&2
  exit 1
fi

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  arm64)  TARGET="aarch64-apple-darwin" ;;
  x86_64) TARGET="x86_64-apple-darwin" ;;
  *)
    echo "Error: unsupported architecture: $ARCH" >&2
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
ACTUAL="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Error: checksum mismatch" >&2
  echo "  expected: $EXPECTED" >&2
  echo "  actual:   $ACTUAL" >&2
  exit 1
fi

# Extract and install
tar xzf "$TARBALL"
install -d "$INSTALL_DIR"
install -m 755 s2 "$INSTALL_DIR/s2"

echo "Installed s2 ${VERSION} to ${INSTALL_DIR}/s2"
