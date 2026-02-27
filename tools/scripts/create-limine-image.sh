#!/bin/bash

# Script to create bootable disk image with Limine

set -e

BUILD_DIR="build"
LIMINE_DIR="$BUILD_DIR/limine"
ISO_ROOT="$BUILD_DIR/iso_root"
IMAGE_BASENAME="${STRAT9_IMAGE_BASENAME:-strat9-os}"
PROFILE="${STRAT9_PROFILE:-debug}"
IMAGE_FILE="$BUILD_DIR/${IMAGE_BASENAME}.img"
ISO_FILE="$BUILD_DIR/${IMAGE_BASENAME}.iso"
KERNEL_ELF="target/x86_64-unknown-none/${PROFILE}/kernel"
FS_EXT4_ELF="target/x86_64-unknown-none/${PROFILE}/fs-ext4-strate"
FS_RAM_ELF="target/x86_64-unknown-none/${PROFILE}/strate-fs-ramfs"
INIT_TEST_ELF="target/x86_64-unknown-none/${PROFILE}/test_pid"
SYSCALL_TEST_ELF="target/x86_64-unknown-none/${PROFILE}/test_syscalls"
MEM_TEST_ELF="target/x86_64-unknown-none/${PROFILE}/test_mem"
MEM_STRESSED_ELF="target/x86_64-unknown-none/${PROFILE}/test_mem_stressed"
INIT_ELF="target/x86_64-unknown-none/${PROFILE}/init"
CONSOLE_ADMIN_ELF="target/x86_64-unknown-none/${PROFILE}/console-admin"
NET_ELF="target/x86_64-unknown-none/${PROFILE}/strate-net-silo"
DHCP_CLIENT_ELF="target/x86_64-unknown-none/${PROFILE}/dhcp-client"
PING_ELF="target/x86_64-unknown-none/${PROFILE}/ping"

echo ""
echo "=== Creating Limine bootable image ==="
echo "Profile: ${PROFILE}"
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
    echo "    strate-fs-ramfs : $ram_size bytes"
else
    echo "    strate-fs-ramfs : (missing)"
fi
if [ -f "$INIT_TEST_ELF" ]; then
    init_size=$(stat -c%s "$INIT_TEST_ELF")
    echo "    init-test   : $init_size bytes"
else
    echo "    init-test   : (missing)"
fi
if [ -f "$SYSCALL_TEST_ELF" ]; then
    syscall_test_size=$(stat -c%s "$SYSCALL_TEST_ELF")
    echo "    syscall-test: $syscall_test_size bytes"
else
    echo "    syscall-test: (missing)"
fi
if [ -f "$MEM_TEST_ELF" ]; then
    mem_test_size=$(stat -c%s "$MEM_TEST_ELF")
    echo "    mem-test    : $mem_test_size bytes"
else
    echo "    mem-test    : (missing)"
fi
if [ -f "$MEM_STRESSED_ELF" ]; then
    mem_stressed_size=$(stat -c%s "$MEM_STRESSED_ELF")
    echo "    mem-stressed: $mem_stressed_size bytes"
else
    echo "    mem-stressed: (missing)"
fi
if [ -f "$INIT_ELF" ]; then
    init_real_size=$(stat -c%s "$INIT_ELF")
    echo "    init        : $init_real_size bytes"
else
    echo "    init        : (missing)"
fi
if [ -f "$CONSOLE_ADMIN_ELF" ]; then
    ca_size=$(stat -c%s "$CONSOLE_ADMIN_ELF")
    echo "    console-admin: $ca_size bytes"
else
    echo "    console-admin: (missing)"
fi
if [ -f "$NET_ELF" ]; then
    net_size=$(stat -c%s "$NET_ELF")
    echo "    strate-net   : $net_size bytes"
else
    echo "    strate-net   : (missing)"
fi
if [ -f "$DHCP_CLIENT_ELF" ]; then
    dhcp_client_size=$(stat -c%s "$DHCP_CLIENT_ELF")
    echo "    dhcp-client  : $dhcp_client_size bytes"
else
    echo "    dhcp-client  : (missing)"
fi
if [ -f "$PING_ELF" ]; then
    ping_size=$(stat -c%s "$PING_ELF")
    echo "    ping         : $ping_size bytes"
else
    echo "    ping         : (missing)"
fi
echo ""

# Create ISO root structure
rm -rf "$ISO_ROOT"
mkdir -p "$ISO_ROOT/boot/limine"
mkdir -p "$ISO_ROOT/initfs"
mkdir -p "$ISO_ROOT/initfs/bin"

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
    cp "$FS_EXT4_ELF" "$ISO_ROOT/initfs/fs-ext4"
    cp "$FS_EXT4_ELF" "$ISO_ROOT/initfs/fs-ext4-strate"
    echo "  [OK] Copied fs-ext4 (aliases: fs-ext4 + fs-ext4-strate)"
else
    echo "  [WARN] fs-ext4 strate not found at $FS_EXT4_ELF"
fi

if [ -f "$FS_RAM_ELF" ]; then
    cp "$FS_RAM_ELF" "$ISO_ROOT/initfs/strate-fs-ramfs"
    echo "  [OK] Copied strate-fs-ramfs"
else
    echo "  [WARN] strate-fs-ramfs not found at $FS_RAM_ELF"
fi

if [ -f "$INIT_TEST_ELF" ]; then
    cp "$INIT_TEST_ELF" "$ISO_ROOT/initfs/test_pid"
    echo "  [OK] Copied init-test binary: /initfs/test_pid"
else
    echo "  ERROR: init-test binary not found at $INIT_TEST_ELF"
    echo "  Build it first (e.g. cargo make strate-silo-test or strate-silo-test-release)"
    exit 1
fi

if [ -f "$SYSCALL_TEST_ELF" ]; then
    cp "$SYSCALL_TEST_ELF" "$ISO_ROOT/initfs/test_syscalls"
    echo "  [OK] Copied syscall-test binary: /initfs/test_syscalls"
else
    echo "  [WARN] syscall-test binary not found at $SYSCALL_TEST_ELF"
fi

if [ -f "$MEM_TEST_ELF" ]; then
    cp "$MEM_TEST_ELF" "$ISO_ROOT/initfs/test_mem"
    echo "  [OK] Copied mem-test binary: /initfs/test_mem"
else
    echo "  [WARN] mem-test binary not found at $MEM_TEST_ELF"
fi

if [ -f "$MEM_STRESSED_ELF" ]; then
    cp "$MEM_STRESSED_ELF" "$ISO_ROOT/initfs/test_mem_stressed"
    echo "  [OK] Copied mem-stressed binary: /initfs/test_mem_stressed"
else
    echo "  [WARN] mem-stressed binary not found at $MEM_STRESSED_ELF"
fi

if [ -f "$INIT_ELF" ]; then
    cp "$INIT_ELF" "$ISO_ROOT/initfs/init"
    echo "  [OK] Copied init binary: /initfs/init"
else
    echo "  [WARN] init binary not found at $INIT_ELF"
fi

if [ -f "$CONSOLE_ADMIN_ELF" ]; then
    cp "$CONSOLE_ADMIN_ELF" "$ISO_ROOT/initfs/console-admin"
    echo "  [OK] Copied console-admin binary: /initfs/console-admin"
else
    echo "  [WARN] console-admin binary not found at $CONSOLE_ADMIN_ELF"
fi

if [ -f "$NET_ELF" ]; then
    cp "$NET_ELF" "$ISO_ROOT/initfs/strate-net"
    echo "  [OK] Copied strate-net: /initfs/strate-net"
else
    echo "  [WARN] strate-net binary not found at $NET_ELF"
fi

if [ -f "$DHCP_CLIENT_ELF" ]; then
    cp "$DHCP_CLIENT_ELF" "$ISO_ROOT/initfs/bin/dhcp-client"
    echo "  [OK] Copied dhcp-client: /initfs/bin/dhcp-client"
else
    echo "  [WARN] dhcp-client binary not found at $DHCP_CLIENT_ELF"
fi

if [ -f "$PING_ELF" ]; then
    cp "$PING_ELF" "$ISO_ROOT/initfs/bin/ping"
    echo "  [OK] Copied ping: /initfs/bin/ping"
else
    echo "  [WARN] ping binary not found at $PING_ELF"
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
