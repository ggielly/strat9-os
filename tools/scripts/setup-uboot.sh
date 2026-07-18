#!/bin/bash

# Script to download and build U-Boot bootloader
# Supports x86_64, riscv64, and aarch64

set -e

BUILD_DIR="build"
UBOOT_DIR="$BUILD_DIR/uboot"
UBOOT_VERSION="v2026.07"

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

# Build for target architecture
ARCH="${1:-x86_64}"

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

echo ""
echo "=== U-Boot setup complete ==="
echo "  Binary: $UBOOT_DIR/u-boot.bin"
echo "  Arch: $ARCH"
echo ""
