#!/bin/bash
# Build kpmctl using NDK (static binary for Android aarch64)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Load .env if exists
if [ -f "$PROJECT_ROOT/.env" ]; then
    export $(grep -v '^#' "$PROJECT_ROOT/.env" | grep -v '^$' | xargs)
fi

# Detect platform
ARCH=$(uname -m)
OS=$(uname -s)
if [ "$OS" = "Darwin" ]; then
    if [ "$ARCH" = "arm64" ]; then
        PLATFORM="darwin-aarch64"
        PLATFORM_FALLBACK="darwin-x86_64"
    else
        PLATFORM="darwin-x86_64"
    fi
elif [ "$OS" = "Linux" ]; then
    if [ "$ARCH" = "aarch64" ]; then
        PLATFORM="linux-aarch64"
        PLATFORM_FALLBACK="linux-x86_64"
    else
        PLATFORM="linux-x86_64"
    fi
else
    echo -e "${RED}[-] Unsupported OS: $OS${NC}"
    exit 1
fi

# Find NDK
find_ndk() {
    local paths=()
    if [ "$OS" = "Darwin" ]; then
        paths=(
            "$HOME/Library/Android/sdk/ndk"
            "/usr/local/share/android-ndk"
        )
    else
        paths=(
            "$HOME/Android/Sdk/ndk"
            "/opt/android-ndk"
        )
    fi

    for base in "${paths[@]}"; do
        if [ -d "$base" ]; then
            for ver in "$base"/*/; do
                if [ -d "${ver}toolchains/llvm/prebuilt/${PLATFORM}" ]; then
                    echo "${ver%/}"
                    return 0
                fi
                if [ -n "$PLATFORM_FALLBACK" ] && [ -d "${ver}toolchains/llvm/prebuilt/${PLATFORM_FALLBACK}" ]; then
                    PLATFORM="$PLATFORM_FALLBACK"
                    echo "${ver%/}"
                    return 0
                fi
            done
        fi
    done
    return 1
}

if [ -z "$NDK_PATH" ]; then
    NDK_PATH=$(find_ndk) || true
fi

if [ -z "$NDK_PATH" ]; then
    echo -e "${RED}[-] NDK not found. Set NDK_PATH or install Android NDK.${NC}"
    exit 1
fi

# Re-detect actual platform directory in NDK
if [ ! -d "${NDK_PATH}/toolchains/llvm/prebuilt/${PLATFORM}" ]; then
    if [ -n "$PLATFORM_FALLBACK" ] && [ -d "${NDK_PATH}/toolchains/llvm/prebuilt/${PLATFORM_FALLBACK}" ]; then
        PLATFORM="$PLATFORM_FALLBACK"
    else
        # Auto-detect: pick whatever exists
        PLATFORM=$(ls "${NDK_PATH}/toolchains/llvm/prebuilt/" | head -1)
    fi
fi

echo -e "${GREEN}[*] NDK: ${NDK_PATH}${NC}"
echo -e "${GREEN}[*] Platform: ${PLATFORM}${NC}"

TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt/${PLATFORM}/bin"
CC="${TOOLCHAIN}/aarch64-linux-android31-clang"
STRIP="${TOOLCHAIN}/llvm-strip"

if [ ! -f "$CC" ]; then
    echo -e "${RED}[-] Compiler not found: $CC${NC}"
    exit 1
fi

OUTPUT="$SCRIPT_DIR/kpmctl"

echo -e "${YELLOW}[*] Compiling kpmctl...${NC}"
"$CC" -O2 -Wall -static -o "$OUTPUT" "$SCRIPT_DIR/kpmctl.c"

echo -e "${YELLOW}[*] Stripping...${NC}"
"$STRIP" "$OUTPUT"

ls -lh "$OUTPUT"
echo -e "${GREEN}[+] Build complete: $OUTPUT${NC}"
