#!/bin/bash

# Script to create bootable disk image with U-Boot
# Creates a GPT disk with FAT32 boot partition containing kernel + modules

set -e

BUILD_DIR="build"
UBOOT_DIR="$BUILD_DIR/uboot"
IMAGE_BASENAME="${STRAT9_IMAGE_BASENAME:-strat9-os}"
PROFILE="${STRAT9_PROFILE:-debug}"
IMAGE_FILE="$BUILD_DIR/${IMAGE_BASENAME}.img"
BOOT_PART_SIZE_MB=64

# Source paths
TARGET_DIR="target/x86_64-unknown-none/${PROFILE}"
KERNEL_ELF="$TARGET_DIR/kernel"
MODULES_DIR="workspace/modules"

echo ""
echo "=== Creating U-Boot bootable image ==="
echo "Profile: ${PROFILE}"
echo ""

# Check if U-Boot is built
if [ ! -f "$UBOOT_DIR/u-boot.bin" ]; then
    echo "ERROR: U-Boot not found. Run 'cargo make setup-uboot' first"
    exit 1
fi

# Check if kernel exists
if [ ! -f "$KERNEL_ELF" ]; then
    echo "ERROR: Kernel not found at $KERNEL_ELF"
    echo "  Build the kernel first with 'cargo make kernel'"
    exit 1
fi

kernel_size=$(stat -c%s "$KERNEL_ELF")
echo "  Kernel ELF: $kernel_size bytes"
echo ""

# Create workspace/modules directory structure for FAT32
echo "  --- Preparing boot modules ---"
MOD_STAGING="$BUILD_DIR/mod_staging"
rm -rf "$MOD_STAGING"
mkdir -p "$MOD_STAGING/boot"
mkdir -p "$MOD_STAGING/modules"

# Copy kernel
cp "$KERNEL_ELF" "$MOD_STAGING/boot/kernel.elf"

# Copy userspace modules
MODULES=(
    "fs-ext4-strate:fs-ext4"
    "strate-fs-ramfs:strate-fs-ramfs"
    "strate-init:init"
    "console-admin:console-admin"
    "strate-net-silo:strate-net"
    "strate-bus:strate-bus"
    "strate-wasm:strate-wasm"
    "strate-webrtc:strate-webrtc"
    "dhcp-client:bin/dhcp-client"
    "ping:bin/ping"
    "telnetd:bin/telnetd"
    "udp-tool:bin/udp-tool"
    "web-admin:bin/web-admin"
    "test_pid:test_pid"
    "test_syscalls:test_syscalls"
    "test_mem:test_mem"
    "test_mem_stressed:test_mem_stressed"
    "test_mem_region:test_mem_region"
    "test_mem_region_proc:test_mem_region_proc"
    "test_exec:test_exec"
    "test_exec_helper:test_exec_helper"
)

copied_count=0
for entry in "${MODULES[@]}"; do
    src_name="${entry%%:*}"
    dst_path="${entry##*:}"
    src_file="$TARGET_DIR/$src_name"

    # Create subdirectories as needed
    dst_dir=$(dirname "$MOD_STAGING/modules/$dst_path")
    mkdir -p "$dst_dir"

    if [ -f "$src_file" ]; then
        cp "$src_file" "$MOD_STAGING/modules/$dst_path"
        echo "  [OK] /modules/$dst_path"
        copied_count=$((copied_count + 1))
    else
        echo "  [WARN] $src_name not found at $src_file"
    fi
done

# Auto-discover remaining workspace binaries
echo ""
echo "  --- Auto-discovering workspace binaries ---"
if [ -d "$TARGET_DIR" ]; then
    COPIED=$(mktemp)
    for f in "$MOD_STAGING"/modules/* "$MOD_STAGING"/modules/bin/*; do
        [ -f "$f" ] && basename "$f" >> "$COPIED" 2>/dev/null
    done

    for elf in "$TARGET_DIR"/*; do
        [ -f "$elf" ] || continue
        name=$(basename "$elf")
        case "$name" in
            kernel|*.d|*.rlib|*.rmeta|*.o|lib*|deps) continue ;;
        esac
        if grep -qxF "$name" "$COPIED" 2>/dev/null; then
            continue
        fi
        if file "$elf" 2>/dev/null | grep -q "ELF"; then
            mkdir -p "$MOD_STAGING/modules"
            cp "$elf" "$MOD_STAGING/modules/$name"
            echo "  [OK] Auto-copied: /modules/$name"
        fi
    done
    rm -f "$COPIED"
fi
echo "  --- End auto-discovery ---"
echo ""

# Copy boot config files
SILO_TOML_FILE="workspace/assets/boot/silo.toml"
if [ -f "$SILO_TOML_FILE" ]; then
    cp "$SILO_TOML_FILE" "$MOD_STAGING/modules/silo.toml"
    echo "  [OK] Copied boot config: /modules/silo.toml"
fi

KERNEL_TOML_FILE="workspace/assets/boot/kernel.toml"
if [ -f "$KERNEL_TOML_FILE" ]; then
    cp "$KERNEL_TOML_FILE" "$MOD_STAGING/modules/kernel.toml"
    echo "  [OK] Copied kernel config: /modules/kernel.toml"
fi

HELLO_WASM_FILE="workspace/assets/wasm/hello.wasm"
if [ -f "$HELLO_WASM_FILE" ]; then
    mkdir -p "$MOD_STAGING/modules/bin"
    cp "$HELLO_WASM_FILE" "$MOD_STAGING/modules/bin/hello.wasm"
    echo "  [OK] Copied hello.wasm: /modules/bin/hello.wasm"
fi

WASM_TEST_TOML="workspace/assets/wasm/wasm-test.toml"
if [ -f "$WASM_TEST_TOML" ]; then
    cp "$WASM_TEST_TOML" "$MOD_STAGING/modules/wasm-test.toml"
    echo "  [OK] Copied wasm-test.toml: /modules/wasm-test.toml"
fi

echo ""

# Create raw disk image
echo "  --- Creating disk image ---"
image_size=$((256 * 1024 * 1024))  # 256 MB
dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=256 status=progress

# Create GPT partition table
if command -v parted >/dev/null 2>&1; then
    parted -s "$IMAGE_FILE" mklabel gpt
    parted -s "$IMAGE_FILE" mkpart primary fat32 1MiB "${BOOT_PART_SIZE_MB}MiB"
    parted -s "$IMAGE_FILE" mkpart primary ext4 "${BOOT_PART_SIZE_MB}MiB" 100%
    parted -s "$IMAGE_FILE" set 1 boot on
    echo "  [OK] GPT partition table created"
else
    echo "  [WARN] parted not found, creating simple raw image"
fi

# Write U-Boot to the disk (post-MBR gap or BIOS boot partition)
dd if="$UBOOT_DIR/u-boot.bin" of="$IMAGE_FILE" bs=512 seek=2048 conv=notrunc 2>/dev/null || true
echo "  [OK] U-Boot written to disk"

# Create ISO for CD-ROM boot (optional)
ISO_FILE="$BUILD_DIR/${IMAGE_BASENAME}.iso"
if command -v xorriso >/dev/null 2>&1; then
    echo ""
    echo "  --- Creating ISO ---"

    # Create ISO root with kernel and modules
    ISO_ROOT="$BUILD_DIR/iso_root"
    rm -rf "$ISO_ROOT"
    mkdir -p "$ISO_ROOT/boot"
    mkdir -p "$ISO_ROOT/modules/bin"

    cp "$KERNEL_ELF" "$ISO_ROOT/boot/kernel.elf"
    cp -r "$MOD_STAGING/modules/"* "$ISO_ROOT/modules/" 2>/dev/null || true

    # Copy U-Boot for ISO boot
    mkdir -p "$ISO_ROOT/boot/uboot"
    cp "$UBOOT_DIR/u-boot.bin" "$ISO_ROOT/boot/uboot/"

    xorriso -as mkisofs \
        -b boot/uboot/u-boot.bin \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        --protective-msdos-label \
        "$ISO_ROOT" \
        -o "$ISO_FILE"

    if [ -f "$ISO_FILE" ]; then
        iso_size=$(stat -c%s "$ISO_FILE")
        iso_size_mb=$((iso_size / 1024 / 1024))
        echo "  [OK] ISO created ($iso_size_mb MB)"
    else
        echo "  [ERROR] ISO creation failed"
    fi
fi

# Cleanup
rm -rf "$MOD_STAGING"

echo ""
echo "============================================"
echo "  Kernel Size Summary"
echo "============================================"
echo ""
if [ -f "$KERNEL_ELF" ]; then
    kernel_size=$(stat -c%s "$KERNEL_ELF")
    kernel_size_kb=$((kernel_size / 1024))
    echo "  Kernel ELF: $kernel_size bytes ($kernel_size_kb KB)"
fi
echo ""
echo "============================================"
echo "  U-Boot bootable image created!"
echo "============================================"
echo ""
echo "  Disk image : $IMAGE_FILE"
echo "  ISO file   : $ISO_FILE"
echo ""
echo "  Launch: cargo make run-debug"
echo "============================================"
echo ""
