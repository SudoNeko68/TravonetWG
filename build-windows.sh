#!/usr/bin/env bash
#
# TravonetWG Windows Build Script
# Compiles travonet-wg.exe for Windows (x86_64 and x86)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
OUT_DIR="${PROJECT_ROOT}/build/windows"

GO_BIN="${GO_BIN:-$(which go 2>/dev/null || echo "$HOME/.local/go/bin/go")}"
if [ ! -x "$GO_BIN" ]; then
    echo "Error: Go binary not found at '$GO_BIN'. Please install Go or set GO_BIN." >&2
    exit 1
fi

echo "=========================================================="
echo " TravonetWG Windows Executable Builder"
echo "=========================================================="
echo "Go compiler: $GO_BIN ($($GO_BIN version))"
echo "Output directory: $OUT_DIR"
echo "=========================================================="

mkdir -p "$OUT_DIR"

echo ">>> Building Windows x86_64 executable..."
GOOS=windows GOARCH=amd64 "$GO_BIN" build \
    -trimpath \
    -ldflags="-w -s" \
    -o "$OUT_DIR/travonet-wg.exe" \
    "$PROJECT_ROOT"

echo ">>> Building Windows x86 (32-bit) executable..."
GOOS=windows GOARCH=386 "$GO_BIN" build \
    -trimpath \
    -ldflags="-w -s" \
    -o "$OUT_DIR/travonet-wg-x86.exe" \
    "$PROJECT_ROOT"

echo ""
echo "=========================================================="
echo " Windows binaries built successfully!"
ls -lh "$OUT_DIR"/*.exe
echo "=========================================================="
