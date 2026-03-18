#!/bin/bash
# deploy.sh - One-click build, push, and load KPM modules
#
# Usage:
#   ./deploy.sh <superkey> [module_name]    Build + push + load
#   ./deploy.sh <superkey> --list           List loaded modules on device
#   ./deploy.sh <superkey> --unload <name>  Unload a module
#   ./deploy.sh <superkey> --info <name>    Show module info
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVICE_TMP="/data/local/tmp"
KPMCTL_DEVICE="$DEVICE_TMP/kpmctl"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    echo "deploy.sh - One-click KPM deploy tool"
    echo ""
    echo "Usage:"
    echo "  $0 <superkey> [module_name]      Build + push + load a module (or all)"
    echo "  $0 <superkey> --list             List loaded modules on device"
    echo "  $0 <superkey> --unload <name>    Unload a module by name"
    echo "  $0 <superkey> --info <name>      Show module info"
    echo "  $0 <superkey> --hello            Check if KernelPatch is active"
    echo ""
    echo "Examples:"
    echo "  $0 mysuperkey hello              Build and load 'hello' module"
    echo "  $0 mysuperkey                    Build and load all modules"
    echo "  $0 mysuperkey --list             List what's loaded"
    echo "  $0 mysuperkey --unload kpm-hello Unload kpm-hello"
}

if [ $# -lt 1 ]; then
    usage
    exit 1
fi

SUPERKEY="$1"
shift

# Ensure adb is available
if ! command -v adb &>/dev/null; then
    echo -e "${RED}[-] adb not found in PATH${NC}"
    exit 1
fi

# Build kpmctl if not exists
ensure_kpmctl() {
    local kpmctl_bin="$SCRIPT_DIR/tools/kpmctl/kpmctl"
    if [ ! -f "$kpmctl_bin" ]; then
        echo -e "${YELLOW}[*] Building kpmctl...${NC}"
        bash "$SCRIPT_DIR/tools/kpmctl/build.sh"
    fi

    # Check if kpmctl is on device
    if ! adb shell "[ -f $KPMCTL_DEVICE ]" 2>/dev/null; then
        echo -e "${YELLOW}[*] Pushing kpmctl to device...${NC}"
        adb push "$kpmctl_bin" "$KPMCTL_DEVICE"
        adb shell "chmod 755 $KPMCTL_DEVICE"
    fi
}

# Run kpmctl on device
run_kpmctl() {
    adb shell "$KPMCTL_DEVICE" "$SUPERKEY" "$@"
}

# Handle special commands
if [ $# -ge 1 ]; then
    case "$1" in
        --list)
            ensure_kpmctl
            run_kpmctl list
            exit $?
            ;;
        --hello)
            ensure_kpmctl
            run_kpmctl hello
            exit $?
            ;;
        --unload)
            if [ -z "$2" ]; then
                echo -e "${RED}[-] Usage: $0 <key> --unload <module_name>${NC}"
                exit 1
            fi
            ensure_kpmctl
            run_kpmctl unload "$2"
            exit $?
            ;;
        --info)
            if [ -z "$2" ]; then
                echo -e "${RED}[-] Usage: $0 <key> --info <module_name>${NC}"
                exit 1
            fi
            ensure_kpmctl
            run_kpmctl info "$2"
            exit $?
            ;;
        --help|-h)
            usage
            exit 0
            ;;
    esac
fi

MODULE_NAME="${1:-}"

# Step 1: Build
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Step 1: Build KPM module(s)${NC}"
echo -e "${BLUE}========================================${NC}"

if [ -n "$MODULE_NAME" ]; then
    echo -e "${YELLOW}[*] Building module: $MODULE_NAME${NC}"
    bash "$SCRIPT_DIR/build.sh"
    cmake --build "$SCRIPT_DIR/build" --target "$MODULE_NAME"
else
    echo -e "${YELLOW}[*] Building all modules...${NC}"
    bash "$SCRIPT_DIR/build.sh"
fi

# Step 2: Ensure kpmctl
ensure_kpmctl

# Step 3: Check KernelPatch
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Step 2: Check KernelPatch${NC}"
echo -e "${BLUE}========================================${NC}"
run_kpmctl hello || {
    echo -e "${RED}[-] KernelPatch not active on device. Aborting.${NC}"
    exit 1
}

# Step 4: Push and load
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Step 3: Push & Load${NC}"
echo -e "${BLUE}========================================${NC}"

load_module() {
    local kpm_file="$1"
    local mod_name
    mod_name=$(basename "$kpm_file" .kpm)
    local device_path="$DEVICE_TMP/${mod_name}.kpm"

    echo -e "${YELLOW}[*] Pushing $mod_name.kpm -> $device_path${NC}"
    adb push "$kpm_file" "$device_path"

    echo -e "${YELLOW}[*] Loading $mod_name...${NC}"
    run_kpmctl load "$device_path" || true
}

if [ -n "$MODULE_NAME" ]; then
    KPM_FILE="$SCRIPT_DIR/build/$MODULE_NAME/$MODULE_NAME.kpm"
    if [ ! -f "$KPM_FILE" ]; then
        echo -e "${RED}[-] KPM file not found: $KPM_FILE${NC}"
        exit 1
    fi
    load_module "$KPM_FILE"
else
    # Load all .kpm files
    found=0
    for kpm in "$SCRIPT_DIR"/build/*/*.kpm; do
        if [ -f "$kpm" ]; then
            load_module "$kpm"
            found=1
        fi
    done
    if [ $found -eq 0 ]; then
        echo -e "${RED}[-] No .kpm files found in build/${NC}"
        exit 1
    fi
fi

# Step 5: Verify
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Step 4: Verify${NC}"
echo -e "${BLUE}========================================${NC}"
run_kpmctl list

echo ""
echo -e "${GREEN}[+] Done!${NC}"
