#!/bin/bash

# Script to create a UEFI-bootable disk image for strat9-os
# Creates a FAT32 image containing:
#   /efi/boot/bootx64.efi  - the UEFI bootloader
#   /boot/kernel.elf        - the kernel ELF
#   /boot/initfs/*          - userspace modules

set -e

BUILD_DIR="build"
IMAGE_BASENAME="${STRAT9_IMAGE_BASENAME:-strat9-os}"
PROFILE="${STRAT9_PROFILE:-debug}"
IMAGE_FILE="$BUILD_DIR/${IMAGE_BASENAME}-uefi.img"
BOOTLOADER_EFI="target/x86_64-unknown-uefi/${PROFILE}/strat9-bootloader.efi"
KERNEL_ELF="target/x86_64-unknown-none/${PROFILE}/kernel"

echo ""
echo "=== Creating UEFI bootable image ==="
echo "Profile: ${PROFILE}"
echo ""

# Check prerequisites
if [ ! -f "$BOOTLOADER_EFI" ]; then
    echo "ERROR: UEFI bootloader not found at $BOOTLOADER_EFI"
    echo "  Build with: cargo make bootloader-uefi"
    exit 1
fi

if [ ! -f "$KERNEL_ELF" ]; then
    echo "ERROR: Kernel not found at $KERNEL_ELF"
    echo "  Build with: cargo make kernel"
    exit 1
fi

bootloader_size=$(stat -c%s "$BOOTLOADER_EFI")
kernel_size=$(stat -c%s "$KERNEL_ELF")
echo "  Components:"
echo "    Bootloader EFI: $bootloader_size bytes"
echo "    Kernel ELF    : $kernel_size bytes"

# Create the disk image directory structure
ISO_ROOT="$BUILD_DIR/uefi_iso_root"
rm -rf "$ISO_ROOT"
mkdir -p "$ISO_ROOT/efi/boot"
mkdir -p "$ISO_ROOT/boot/initfs"

# Copy bootloader
cp "$BOOTLOADER_EFI" "$ISO_ROOT/efi/boot/bootx64.efi"
echo "  [OK] Copied bootloader to /efi/boot/bootx64.efi"

# Copy kernel
cp "$KERNEL_ELF" "$ISO_ROOT/boot/kernel.elf"
echo "  [OK] Copied kernel to /boot/kernel.elf"

# Copy userspace modules
MODULES=(
    "strate-init"
    "console-admin"
    "strate-net-silo"
    "strate-bus"
    "fs-ext4-strate"
    "strate-fs-ramfs"
    "strate-wasm"
    "strate-webrtc"
    "display-server"
    "dhcp-client"
    "ping"
    "telnetd"
    "udp-tool"
    "web-admin"
    "test_pid"
    "test_syscalls"
    "test_mem"
)

TARGET_DIR="target/x86_64-unknown-none/${PROFILE}"
for mod in "${MODULES[@]}"; do
    src="$TARGET_DIR/$mod"
    if [ -f "$src" ]; then
        cp "$src" "$ISO_ROOT/boot/initfs/$mod"
        echo "  [OK] Module: $mod"
    else
        echo "  [WARN] Module not found: $mod"
    fi
done

# Auto-discover remaining ELF binaries
if [ -d "$TARGET_DIR" ]; then
    for elf in "$TARGET_DIR"/*; do
        [ -f "$elf" ] || continue
        name=$(basename "$elf")
        case "$name" in
            kernel|*.d|*.rlib|*.rmeta|*.o|lib*|deps|strat9-bootloader) continue ;;
        esac
        if [ -f "$ISO_ROOT/boot/initfs/$name" ]; then
            continue
        fi
        if file "$elf" 2>/dev/null | grep -q "ELF"; then
            cp "$elf" "$ISO_ROOT/boot/initfs/$name"
            echo "  [OK] Auto-copied: $name"
        fi
    done
fi

echo ""

# ========================================================================
# Create FAT32 image
# ========================================================================
# Simple approach: create a FAT32 filesystem directly (no partition table).
# QEMU can boot this with -drive file=...,format=raw if the firmware supports it.
# For OVMF, we need a proper GPT+ESP. Use mtools if available, else mformat.

IMAGE_SIZE_MB=64

if command -v mtools >/dev/null 2>&1; then
    echo "  Creating FAT32 image with mtools..."

    # Create empty image
    dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=$IMAGE_SIZE_MB 2>/dev/null

    # Format as FAT32 directly (no partition table needed for mtools)
    mkfs.fat -F 32 -n "STRAT9" "$IMAGE_FILE" 2>/dev/null

    # Copy files using mcopy
    mcopy -i "$IMAGE_FILE" -s "$ISO_ROOT/efi" "::/efi"
    mcopy -i "$IMAGE_FILE" -s "$ISO_ROOT/boot" "::/boot"

    echo "  [OK] Created FAT32 image with UEFI bootloader"

elif command -v mkfs.fat >/dev/null 2>&1; then
    echo "  Creating FAT32 image with mkfs.fat..."

    dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=$IMAGE_SIZE_MB 2>/dev/null
    mkfs.fat -F 32 -n "STRAT9" "$IMAGE_FILE" 2>/dev/null

    # Without mtools, we can't easily copy files into the FAT image
    # Fall back to creating a directory-based image
    echo "  [INFO] mtools not available - creating raw image with files"
    echo "  [INFO] For full UEFI boot, install mtools: apt install mtools"

    # Create a temporary FAT image with files, then copy
    TEMP_FAT="$BUILD_DIR/temp_fat.img"
    dd if=/dev/zero of="$TEMP_FAT" bs=1M count=$IMAGE_SIZE_MB 2>/dev/null
    mkfs.fat -F 32 -n "STRAT9" "$TEMP_FAT" 2>/dev/null

    # Try using mcopy if available (it might be installed but not in PATH)
    if command -v mcopy >/dev/null 2>&1; then
        mcopy -i "$TEMP_FAT" -s "$ISO_ROOT/efi" "::/efi"
        mcopy -i "$TEMP_FAT" -s "$ISO_ROOT/boot" "::/boot"
        mv "$TEMP_FAT" "$IMAGE_FILE"
        echo "  [OK] Created FAT32 image"
    else
        rm -f "$TEMP_FAT"
        echo "  [WARN] Cannot copy files to FAT image without mtools"
        echo "  [INFO] Install mtools: sudo apt install mtools"
    fi

else
    echo "  WARNING: mkfs.fat not found"
    echo "  Creating simple flat image..."
    dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=$IMAGE_SIZE_MB 2>/dev/null
    echo "  [INFO] For UEFI support, install: sudo apt install mtools dosfstools"
fi

echo ""
echo "============================================"
echo "  UEFI Image created!"
echo "============================================"
echo ""
echo "  Bootloader : $BOOTLOADER_EFI ($bootloader_size bytes)"
echo "  Kernel     : $KERNEL_ELF ($kernel_size bytes)"
echo "  Image      : $IMAGE_FILE"
echo ""
echo "--------------------------------------------"
echo "  Launch with: cargo make run-uefi"
echo "============================================"
echo ""
