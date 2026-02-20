#!/bin/bash

# Script to create bootable disk image with Limine

set -e

BUILD_DIR="build"
LIMINE_DIR="$BUILD_DIR/limine"
ISO_ROOT="$BUILD_DIR/iso_root"
IMAGE_BASENAME="${STRAT9_IMAGE_BASENAME:-strat9-os}"
IMAGE_FILE="$BUILD_DIR/${IMAGE_BASENAME}.img"
ISO_FILE="$BUILD_DIR/${IMAGE_BASENAME}.iso"
KERNEL_ELF="target/x86_64-unknown-none/release/kernel"
FS_EXT4_ELF="target/x86_64-unknown-none/release/fs-ext4-strate"
FS_RAM_ELF="target/x86_64-unknown-none/release/strate-ram"

echo ""
echo "=== Creating Limine bootable image ==="
echo ""

# Check if Limine is setup
if [ ! -f "$LIMINE_DIR/limine-bios.sys" ]; then
    echo "ERROR: Limine not found. Run 'cargo make setup-limine' first"
    exit 1
fi

# Check if kernel exists
if [ ! -f "$KERNEL_ELF" ]; then
    echo "ERROR: Kernel not found at $KERNEL_ELF"
    echo "  Build the kernel first with 'cargo make kernel'"
    exit 1
fi

kernel_size=$(stat -c%s "$KERNEL_ELF")
echo "  Components:"
echo "    Kernel ELF : $kernel_size bytes"
if [ -f "$FS_EXT4_ELF" ]; then
    ext4_size=$(stat -c%s "$FS_EXT4_ELF")
    echo "    fs-ext4    : $ext4_size bytes"
else
    echo "    fs-ext4    : (missing)"
fi
if [ -f "$FS_RAM_ELF" ]; then
    ram_size=$(stat -c%s "$FS_RAM_ELF")
    echo "    strate-ram : $ram_size bytes"
else
    echo "    strate-ram : (missing)"
fi
echo ""

# Create ISO root structure
rm -rf "$ISO_ROOT"
mkdir -p "$ISO_ROOT/boot/limine"
mkdir -p "$ISO_ROOT/initfs"

# Copy kernel
cp "$KERNEL_ELF" "$ISO_ROOT/boot/kernel.elf"
echo "  [OK] Copied kernel"

# Copy Limine files
cp "$LIMINE_DIR/limine-bios.sys" "$ISO_ROOT/boot/limine/"
cp "$LIMINE_DIR/limine-bios-cd.bin" "$ISO_ROOT/boot/limine/"
cp "$LIMINE_DIR/limine-uefi-cd.bin" "$ISO_ROOT/boot/limine/"
echo "  [OK] Copied Limine bootloader"

# Copy config (v8.x uses limine.conf)
cp "limine.conf" "$ISO_ROOT/boot/limine/"
echo "  [OK] Copied configuration"

# Copy userspace modules (initfs)
if [ -f "$FS_EXT4_ELF" ]; then
    cp "$FS_EXT4_ELF" "$ISO_ROOT/initfs/fs-ext4-strate"
    echo "  [OK] Copied fs-ext4 strate"
else
    echo "  [WARN] fs-ext4 strate not found at $FS_EXT4_ELF"
fi

if [ -f "$FS_RAM_ELF" ]; then
    cp "$FS_RAM_ELF" "$ISO_ROOT/initfs/strate-ram"
    echo "  [OK] Copied strate-ram"
else
    echo "  [WARN] strate-ram not found at $FS_RAM_ELF"
fi

# Create ISO using xorriso
if command -v xorriso >/dev/null 2>&1; then
    echo "  Creating ISO with xorriso..."
    
    xorriso -as mkisofs \
        -b boot/limine/limine-bios-cd.bin \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        --efi-boot boot/limine/limine-uefi-cd.bin \
        -efi-boot-part \
        --efi-boot-image \
        --protective-msdos-label \
        "$ISO_ROOT" \
        -o "$ISO_FILE"
    
    # Check if the ISO was created successfully
    if [ -f "$ISO_FILE" ]; then
        iso_size=$(stat -c%s "$ISO_FILE")
        iso_size_mb=$((iso_size / 1024 / 1024))
        if [ $iso_size -gt 1048576 ]; then  # Check if ISO has reasonable size (>1MB)
            echo "  [OK] ISO created ($iso_size_mb MB)"
            
            # Install Limine to ISO (only run executable if it is native executable for this host)
            if [ -f "$LIMINE_DIR/limine" ] || [ -f "$LIMINE_DIR/limine.exe" ]; then
                # Prefer native 'limine' binary when present
                if [ -f "$LIMINE_DIR/limine" ]; then
                    limine_cmd="$LIMINE_DIR/limine"
                    if "$limine_cmd" bios-install "$ISO_FILE"; then
                        echo "  [OK] Limine installed to ISO"
                    else
                        echo "  [INFO] Limine install failed (limine returned non-zero), but ISO is bootable"
                    fi
                fi

                # If only limine.exe is present, check its file type before trying to execute it
                if [ -f "$LIMINE_DIR/limine.exe" ] && [ ! -f "$LIMINE_DIR/limine" ]; then
                    file_out=$(file -b "$LIMINE_DIR/limine.exe" 2>/dev/null || true)
                    # Only attempt to run it if 'ELF' (native Linux binary) is reported
                    if echo "$file_out" | grep -qi 'ELF'; then
                        if "$LIMINE_DIR/limine.exe" bios-install "$ISO_FILE"; then
                            echo "  [OK] Limine installed to ISO (limine.exe executed)"
                        else
                            echo "  [INFO] Limine install failed (limine.exe), but ISO is bootable"
                        fi
                    else
                        echo "  [INFO] Found limine.exe (not an ELF/native binary: $file_out) — skipping execution on this host. ISO is still bootable."
                    fi
                fi
            fi
            
            # Also create a raw disk image for QEMU
            image_size=$((64 * 1024 * 1024))  # 64 MB
            dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=64 >/dev/null 2>&1
            
            echo "  [OK] Created raw disk image"
        else
            echo "  ERROR: xorriso created empty or tiny ISO"
            exit 1
        fi
    else
        echo "  ERROR: xorriso failed to create ISO"
        exit 1
    fi
else
    echo "  WARNING: xorriso not found, creating simple flat image"
    
    # Fallback: create a simple flat image
    image_size=$((64 * 1024 * 1024))  # 64 MB
    dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=64 >/dev/null 2>&1
    
    echo "  [OK] Created disk image"
    echo ""
    echo "  NOTE: For full UEFI/BIOS support, install xorriso"
fi

# Kernel size summary
echo "============================================"
echo "  Kernel Size Summary"
echo "============================================"
echo ""

if [ -f "$KERNEL_ELF" ]; then
    kernel_size=$(stat -c%s "$KERNEL_ELF")
    kernel_size_kb=$((kernel_size / 1024))
    echo "  Kernel ELF: $kernel_size bytes ($kernel_size_kb KB)"
    
    # Show section breakdown if size command is available
    if command -v size >/dev/null 2>&1; then
        echo ""
        echo "  Section breakdown:"
        size "$KERNEL_ELF" | tail -n 1 | awk '{printf "    .text: %s bytes\n    .data: %s bytes\n    .bss:  %s bytes\n", $2, $3, $4}'
    fi
fi

echo ""
echo "============================================"
echo "  Bootable image created!"
echo "============================================"
echo ""
echo "  ISO file  : $ISO_FILE"
echo "  Disk image: $IMAGE_FILE"
echo ""
echo "--------------------------------------------"
echo "  Launch with: cargo make run"
echo "============================================"
echo ""
