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
cp "$BOOTLOADER_EFI" "$ISO_ROOT/efi/boot/BOOTX64.EFI"
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
# Create GPT + EFI System Partition image
# ========================================================================
# OVMF requires a GPT-formatted disk with an EFI System Partition (ESP).
# The ESP must be FAT32 and contain /efi/boot/bootx64.efi.

IMAGE_SIZE_MB=128
SECTOR_SIZE=512

# ESP size: 64MB
ESP_SIZE_MB=64

if command -v parted >/dev/null 2>&1 && command -v mtools >/dev/null 2>&1; then
    echo "  Creating GPT + ESP image with parted + mtools..."

    # Create empty image (128MB to have room for GPT headers)
    dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=$IMAGE_SIZE_MB 2>/dev/null

    # Create GPT partition table and EFI System Partition
    parted -s "$IMAGE_FILE" mklabel gpt
    parted -s "$IMAGE_FILE" mkpart primary fat32 1MiB ${ESP_SIZE_MB}MiB
    parted -s "$IMAGE_FILE" set 1 esp on

    # Calculate offset (1MiB = 2048 sectors)
    ESP_START_SECTOR=2048
    ESP_SIZE_SECTORS=$((ESP_SIZE_MB * 1024 * 1024 / SECTOR_SIZE))

    # Create a temporary FAT32 image for the ESP
    ESP_IMG="$BUILD_DIR/esp.img"
    dd if=/dev/zero of="$ESP_IMG" bs=512 count=$ESP_SIZE_SECTORS 2>/dev/null
    mkfs.fat -F 32 -n "EFI" "$ESP_IMG" 2>/dev/null

    # Copy files into the ESP
    mcopy -i "$ESP_IMG" -s "$ISO_ROOT/efi" "::/efi"
    mcopy -i "$ESP_IMG" -s "$ISO_ROOT/boot" "::/boot"

    # Write the ESP into the disk image at the partition offset
    dd if="$ESP_IMG" of="$IMAGE_FILE" bs=512 seek=$ESP_START_SECTOR conv=notrunc 2>/dev/null
    rm -f "$ESP_IMG"

    echo "  [OK] Created GPT image with EFI System Partition"

elif command -v mtools >/dev/null 2>&1; then
    echo "  Creating FAT32 image with mtools (no GPT - may not boot with OVMF)..."

    dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=$IMAGE_SIZE_MB 2>/dev/null
    mkfs.fat -F 32 -n "STRAT9" "$IMAGE_FILE" 2>/dev/null

    mcopy -i "$IMAGE_FILE" -s "$ISO_ROOT/efi" "::/efi"
    mcopy -i "$IMAGE_FILE" -s "$ISO_ROOT/boot" "::/boot"

    echo "  [OK] Created FAT32 image (install parted for GPT support)"
    echo "  [WARN] Without GPT, OVMF may not find the bootloader"

else
    echo "  WARNING: Neither parted nor mtools found"
    echo "  Creating simple flat image..."
    dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=$IMAGE_SIZE_MB 2>/dev/null
    echo "  [INFO] For UEFI support, install: sudo apt install parted mtools"
fi

echo ""
echo "============================================"
echo "  UEFI Image created!"
echo "============================================"
echo ""
echo "  Bootloader : $BOOTLOADER_EFI ($bootloader_size bytes)"
echo "  Kernel     : $KERNEL_ELF ($kernel_size bytes)"
echo "  Modules    : $(ls -1 "$ISO_ROOT/boot/initfs/" 2>/dev/null | wc -l) file(s)"
echo ""
echo "  Image file:"
echo "    Path     : $IMAGE_FILE"
if [ -f "$IMAGE_FILE" ]; then
    img_size=$(stat -c%s "$IMAGE_FILE" 2>/dev/null || stat -f%z "$IMAGE_FILE" 2>/dev/null)
    img_kb=$((img_size / 1024))
    img_mb=$((img_kb / 1024))
    echo "    Size     : $img_size bytes ($img_kb KB, ~${img_mb} MB)"
    echo "    Type     : $(file -b "$IMAGE_FILE" 2>/dev/null | head -c 80)"
    if command -v parted >/dev/null 2>&1; then
        echo "    Partitions:"
        parted -s "$IMAGE_FILE" print 2>/dev/null | grep -E "^ [0-9]" | while read -r line; do
            echo "      $line"
        done
    fi
fi
echo ""
echo "  All build artifacts:"
echo "    build/"
ls -lh "$BUILD_DIR"/*.img "$BUILD_DIR"/*.iso "$BUILD_DIR"/*.efi 2>/dev/null | while read -r line; do
    echo "      $line"
done
echo ""
echo "--------------------------------------------"
echo "  Launch with: cargo make run-uefi"
echo "============================================"
echo ""
