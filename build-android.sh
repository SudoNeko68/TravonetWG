#!/usr/bin/env bash
#
# TravonetWG Android Native Library Build Script
# Compiles libtravonet-wg.so for arm64-v8a, armeabi-v7a, x86_64, and x86.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
OUT_DIR="${PROJECT_ROOT}/build/android/jniLibs"

# Detect Go
GO_BIN="${GO_BIN:-$(which go 2>/dev/null || echo "$HOME/.local/go/bin/go")}"
if [ ! -x "$GO_BIN" ]; then
    echo "Error: Go binary not found at '$GO_BIN'. Please install Go or set GO_BIN." >&2
    exit 1
fi

# Detect NDK
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${ANDROID_NDK_ROOT:-}" ]; then
    for cand in \
        "$HOME/Android/Sdk/ndk/"* \
        "/opt/android-sdk/ndk/"* \
        "/opt/android-ndk/"* \
        "${ANDROID_HOME:-}/ndk/"*; do
        if [ -d "$cand/toolchains/llvm/prebuilt/linux-x86_64/bin" ]; then
            ANDROID_NDK_HOME="$cand"
        fi
    done
fi

ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "Error: ANDROID_NDK_HOME is not set and could not be auto-detected." >&2
    exit 1
fi

TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [ ! -d "$TOOLCHAIN" ]; then
    echo "Error: Toolchain directory '$TOOLCHAIN' does not exist." >&2
    exit 1
fi

echo "=========================================================="
echo " TravonetWG Android Native Library Builder"
echo "=========================================================="
echo "Go compiler: $GO_BIN ($($GO_BIN version))"
echo "Android NDK: $ANDROID_NDK_HOME"
echo "Output directory: $OUT_DIR"
echo "=========================================================="

API_LEVEL=21

# Architectures to build:
# Format: <ABI_NAME> <GOARCH> <GOARM> <CLANG_PREFIX>
ABIS=(
    "arm64-v8a  arm64  -  aarch64-linux-android"
    "armeabi-v7a arm    7  armv7a-linux-androideabi"
    "x86_64     amd64  -  x86_64-linux-android"
    "x86        386    -  i686-linux-android"
)

mkdir -p "$OUT_DIR"

for entry in "${ABIS[@]}"; do
    read -r ABI GOARCH GOARM CLANG_PREFIX <<< "$entry"
    echo ""
    echo ">>> Building for ABI: $ABI (GOARCH=$GOARCH, API=$API_LEVEL)..."

    CC_BIN="$TOOLCHAIN/${CLANG_PREFIX}${API_LEVEL}-clang"
    if [ ! -x "$CC_BIN" ]; then
        echo "Error: Compiler '$CC_BIN' not found!" >&2
        exit 1
    fi

    ABI_OUT_DIR="$OUT_DIR/$ABI"
    mkdir -p "$ABI_OUT_DIR"

    TARGET_SO="$ABI_OUT_DIR/libtravonet-wg.so"
    WG_GO_SO="$ABI_OUT_DIR/libwg-go.so"

    export CC="$CC_BIN"
    export CGO_ENABLED=1
    export GOOS=android
    export GOARCH="$GOARCH"
    if [ "$GOARM" != "-" ]; then
        export GOARM="$GOARM"
    else
        unset GOARM
    fi

    # Build shared library with CGO
    "$GO_BIN" build \
        -trimpath \
        -ldflags="-w -s" \
        -buildmode=c-shared \
        -o "$TARGET_SO" \
        "$PROJECT_ROOT/android"

    # Remove temporary generated C header in output if not needed
    rm -f "$ABI_OUT_DIR/libtravonet-wg.h"

    # Also create libwg-go.so copy for 100% drop-in compatibility with WireGuard Android
    cp -f "$TARGET_SO" "$WG_GO_SO"

    SO_SIZE=$(ls -lh "$TARGET_SO" | awk '{print $5}')
    echo ">>> Successfully built $ABI -> $TARGET_SO ($SO_SIZE)"
done

echo ""
echo "=========================================================="
echo " All Android native libraries built successfully!"
echo " Output files in: $OUT_DIR"
ls -lh "$OUT_DIR"/*/*.so
echo "=========================================================="
