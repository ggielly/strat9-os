#!/bin/bash

# Script to download and build U-Boot bootloader
# Supports x86_64, riscv64, and aarch64
#
# Usage:
#   ./setup-uboot.sh [arch]           - build only if u-boot.bin is missing
#   ./setup-uboot.sh --force [arch]   - always rebuild
#   ./setup-uboot.sh --update [arch]  - git pull then rebuild only if needed

set -e

BUILD_DIR="build"
UBOOT_DIR="$BUILD_DIR/uboot"
UBOOT_VERSION="v2026.07"
FORCE=0
UPDATE=0

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --update) UPDATE=1 ;;
    esac
done

# Strip flags to get architecture
ARCH=""
for arg in "$@"; do
    case "$arg" in
        --force|--update) continue ;;
        *) ARCH="$arg" ;;
    esac
done
ARCH="${ARCH:-x86_64}"

echo "=== Setting up U-Boot bootloader ==="

# Create build directory
mkdir -p "$BUILD_DIR"

# Clone U-Boot if not already present
if [ ! -d "$UBOOT_DIR" ]; then
    echo "Cloning U-Boot $UBOOT_VERSION using github..."
    if git clone https://github.com/u-boot/u-boot.git "$UBOOT_DIR"; then
        echo "  Cloned successfully"
    else
        echo "  ERROR: failed to clone U-Boot"
        echo "  Try manually: git clone https://github.com/u-boot/u-boot.git $UBOOT_DIR"
        exit 1
    fi
    cd "$UBOOT_DIR" && git checkout "$UBOOT_VERSION" && cd -
else
    echo "U-Boot directory already exists, skipping clone."
fi

# --update: pull latest and decide if rebuild is needed
NEED_BUILD=1
if [ "$UPDATE" -eq 1 ]; then
    echo ""
    echo "Pulling latest U-Boot sources using github..."
    cd "$UBOOT_DIR"
    git fetch origin 2>/dev/null || true
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse "origin/$UBOOT_VERSION" 2>/dev/null || echo "$LOCAL")
    cd - > /dev/null
    if [ "$LOCAL" = "$REMOTE" ]; then
        echo "  Sources up to date."
        if [ "$FORCE" -eq 0 ] && [ -f "$UBOOT_DIR/u-boot.bin" ]; then
            NEED_BUILD=0
            echo "  w00t, binary exists, skipping build \o/."
        fi
    else
        echo "  New changes available, rebuilding..."
        cd "$UBOOT_DIR"
        git pull --ff-only 2>/dev/null || true
        git checkout "$UBOOT_VERSION" 2>/dev/null || true
        cd - > /dev/null
    fi
elif [ "$FORCE" -eq 0 ]; then
    # No flags: skip build if binary already exists
    if [ -f "$UBOOT_DIR/u-boot.bin" ]; then
        NEED_BUILD=0
        echo ""
        echo "  U-Boot binary already exists ($UBOOT_DIR/u-boot.bin)"
        echo "  Skipping build. Use --force to rebuild or --update to pull + rebuild."
    fi
fi

if [ "$NEED_BUILD" -eq 1 ]; then
    case "$ARCH" in
        x86_64|x86)
            DEFCONFIG="qemu-x86_64_defconfig"
            ;;
        riscv64|riscv)
            DEFCONFIG="qemu-riscv64_smode_defconfig"
            ;;
        aarch64|arm64|arm)
            DEFCONFIG="qemu_arm64_defconfig"
            ;;
        *)
            echo "ERROR: Unknown architecture: $ARCH"
            echo "Supported: x86_64, riscv64, aarch64"
            exit 1
            ;;
    esac

    echo ""
    echo "Building U-Boot for $ARCH ($DEFCONFIG)..."
    cd "$UBOOT_DIR"
    make "$DEFCONFIG"
    make -j"$(nproc)"
fi

echo ""
echo "=== U-Boot setup complete ==="
echo "  Binary: $UBOOT_DIR/u-boot.bin"
echo "  Arch: $ARCH"
echo ""
