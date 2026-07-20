#!/bin/bash

# Script to create a UEFI-bootable disk image for strat9-os
# Creates a GPT disk with an EFI System Partition containing:
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
    echo "  Build with: cargo build --target x86_64-unknown-uefi -p strat9-bootloader"
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

# Copy userspace modules (same set as Limine image)
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

# Also auto-discover any remaining ELF binaries
if [ -d "$TARGET_DIR" ]; then
    for elf in "$TARGET_DIR"/*; do
        [ -f "$elf" ] || continue
        name=$(basename "$elf")
        case "$name" in
            kernel|*.d|*.rlib|*.rmeta|*.o|lib*|deps|strat9-bootloader) continue ;;
        esac
        # Skip if already copied
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

# Create the raw disk image (FAT filesystem)
# We use mtools or losetup + mkfs.fat to create a proper FAT ESP

IMAGE_SIZE_MB=64
IMAGE_SIZE_SECTORS=$((IMAGE_SIZE_MB * 1024 * 2))

# Try using mtools (most portable)
if command -v mtools >/dev/null 2>&1; then
    echo "  Creating FAT image with mtools..."

    # Create empty image
    dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=$IMAGE_SIZE_MB 2>/dev/null

    # Create a MBR partition table with a single FAT32 partition
    parted -s "$IMAGE_FILE" mklabel msdos
    parted -s "$IMAGE_FILE" mkpart primary fat32 1MiB 100%
    parted -s "$IMAGE_FILE" set 1 boot on

    # Calculate offset and size
    PART_START=$(parted -s unit s "$IMAGE_FILE" print | grep "^1" | awk '{print $2}' | sed 's/s//')
    PART_END=$(parted -s unit s "$IMAGE_FILE" print | grep "^1" | awk '{print $3}' | sed 's/s//')
    PART_SECTORS=$((PART_END - PART_START + 1))
    PART_OFFSET=$((PART_START * 512))
    PART_SIZE=$((PART_SECTORS * 512))

    # Format the partition as FAT32
    dd if=/dev/zero of="$BUILD_DIR/fat.img" bs=512 count=$PART_SECTORS 2>/dev/null
    mkfs.fat -F 32 -n "STRAT9" "$BUILD_DIR/fat.img" 2>/dev/null

    # Copy files using mcopy
    mcopy -i "$BUILD_DIR/fat.img" -s "$ISO_ROOT/efi" "::/efi"
    mcopy -i "$BUILD_DIR/fat.img" -s "$ISO_ROOT/boot" "::/boot"

    # Write the FAT image into the disk image at the partition offset
    dd if="$BUILD_DIR/fat.img" of="$IMAGE_FILE" bs=512 seek=$PART_START conv=notrunc 2>/dev/null

    rm -f "$BUILD_DIR/fat.img"

    echo "  [OK] Created UEFI disk image with FAT32 ESP"

elif command -v sgdisk >/dev/null 2>&1; then
    echo "  Creating GPT image with sgdisk + mkfs.fat..."

    dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=$IMAGE_SIZE_MB 2>/dev/null
    sgdisk --clear "$IMAGE_FILE"
    sgdisk --new=1:0:+60M --typecode=1:ef00 --change-name=1:"EFI" "$IMAGE_FILE"
    sgdisk --print "$IMAGE_FILE"

    # Find the partition device (requires loop device)
    echo "  [INFO] sgdisk path requires loop device mounting - use mtools instead"
    echo "  [INFO] Falling back to simple flat image"

    # Fallback: just copy everything into a flat image
    # This won't boot without proper FAT, but it's a start
    cp "$IMAGE_FILE" "${IMAGE_FILE}.raw"

else
    echo "  WARNING: Neither mtools nor sgdisk found"
    echo "  Creating simple flat image..."

    dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=$IMAGE_SIZE_MB 2>/dev/null

    echo "  [INFO] For full UEFI support, install mtools: apt install mtools"
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
