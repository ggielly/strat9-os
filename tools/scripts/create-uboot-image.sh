#!/bin/bash
# Create bootable UEFI disk image for Strat9-OS
# Uses OVMF firmware, loads kernel via UEFI boot

set -e

BUILD_DIR="build"
IMAGE_BASENAME="${STRAT9_IMAGE_BASENAME:-strat9-os}"
PROFILE="${STRAT9_PROFILE:-debug}"
IMAGE_FILE="$BUILD_DIR/${IMAGE_BASENAME}.img"

echo ""
echo "=== Creating UEFI bootable image ==="
echo "Profile: ${PROFILE}"
echo ""

# Check kernel
KERNEL_ELF="target/x86_64-unknown-none/${PROFILE}/kernel"
if [ ! -f "$KERNEL_ELF" ]; then
    echo "ERROR: Kernel not found at $KERNEL_ELF"
    exit 1
fi

echo "  Kernel ELF: $(stat -c%s "$KERNEL_ELF") bytes"

# Create disk image
echo ""
echo "  --- Creating GPT disk image ---"
dd if=/dev/zero of="$IMAGE_FILE" bs=1M count=256 status=progress 2>/dev/null

# Create GPT partition table
parted -s "$IMAGE_FILE" mklabel gpt
parted -s "$IMAGE_FILE" mkpart primary fat32 1MiB 64MiB
parted -s "$IMAGE_FILE" set 1 boot on
parted -s "$IMAGE_FILE" mkpart primary ext2 64MiB 100%

# Create FAT32 partition
FAT_IMG="$BUILD_DIR/fat32.img"
dd if=/dev/zero of="$FAT_IMG" bs=1M count=63 2>/dev/null
mkfs.vfat -F 32 "$FAT_IMG"

# Copy files to FAT32
echo "  --- Populating boot partition ---"
mkdir -p /tmp/efi/EFI/BOOT
mkdir -p /tmp/efi/boot
mkdir -p /tmp/efi/modules

# Copy kernel
cp "$KERNEL_ELF" /tmp/efi/boot/kernel.elf
echo "  [OK] kernel.elf"

# Copy U-Boot as EFI application (for real hardware)
if [ -f "$BUILD_DIR/uboot/u-boot-app.efi" ]; then
    cp "$BUILD_DIR/uboot/u-boot-app.efi" /tmp/efi/EFI/BOOT/BOOTX64.EFI
    echo "  [OK] U-Boot EFI app (BOOTX64.EFI)"
elif [ -f "$BUILD_DIR/uboot/u-boot" ]; then
    cp "$BUILD_DIR/uboot/u-boot" /tmp/efi/EFI/BOOT/BOOTX64.EFI
    echo "  [OK] U-Boot (fallback ELF)"
fi

# Create startup.nsh for OVMF auto-boot
cat > /tmp/efi/startup.nsh << 'STARTUP_EOF'
FS0:
cd EFI\BOOT
BOOTX64.EFI
STARTUP_EOF
echo "  [OK] startup.nsh (auto-boot)"

# Copy userspace modules
TARGET_DIR="target/x86_64-unknown-none/${PROFILE}"
MODULES=(
    "strate-init:init"
    "console-admin:console-admin"
    "strate-net-silo:strate-net"
    "strate-bus:strate-bus"
    "fs-ext4-strate:fs-ext4"
    "strate-fs-ramfs:strate-fs-ramfs"
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

for entry in "${MODULES[@]}"; do
    src_name="${entry%%:*}"
    dst_path="${entry##*:}"
    src_file="$TARGET_DIR/$src_name"
    dst_dir=$(dirname "/tmp/efi/modules/$dst_path")
    mkdir -p "$dst_dir"
    if [ -f "$src_file" ]; then
        cp "$src_file" "/tmp/efi/modules/$dst_path"
        echo "  [OK] /modules/$dst_path"
    fi
done

# Auto-discover remaining binaries
if [ -d "$TARGET_DIR" ]; then
    for elf in "$TARGET_DIR"/*; do
        [ -f "$elf" ] || continue
        name=$(basename "$elf")
        case "$name" in
            kernel|*.d|*.rlib|*.rmeta|*.o|lib*|deps) continue ;;
        esac
        if [ -f "/tmp/efi/modules/$name" ]; then
            continue
        fi
        if file "$elf" 2>/dev/null | grep -q "ELF"; then
            cp "$elf" "/tmp/efi/modules/$name"
            echo "  [OK] Auto-copied: /modules/$name"
        fi
    done
fi

# Copy config files
for f in workspace/assets/boot/silo.toml workspace/assets/boot/kernel.toml; do
    if [ -f "$f" ]; then
        cp "$f" "/tmp/efi/modules/$(basename "$f")"
        echo "  [OK] Copied $(basename "$f")"
    fi
done

# Copy WASM files
mkdir -p /tmp/efi/modules/bin
for f in workspace/assets/wasm/hello.wasm workspace/assets/wasm/wasm-test.toml; do
    if [ -f "$f" ]; then
        cp "$f" "/tmp/efi/modules/"
        echo "  [OK] Copied $(basename "$f")"
    fi
done

echo ""

# Write FAT32 to disk
echo "  --- Writing partition data ---"
dd if="$FAT_IMG" of="$IMAGE_FILE" bs=512 seek=2048 conv=notrunc 2>/dev/null
echo "  [OK] FAT32 boot partition written"

# Cleanup
rm -rf "$FAT_IMG" /tmp/efi

echo ""
echo "============================================"
echo "  UEFI bootable image created!"
echo "============================================"
echo ""
echo "  Disk image: $IMAGE_FILE"
echo ""
echo "  Launch with OVMF (x86_64 QEMU):"
echo "    qemu-system-x86_64 -machine q35 -cpu qemu64 -smp 4 -m 2G \\"
echo "      -bios /usr/share/ovmf/OVMF.fd \\"
echo "      -drive file=$IMAGE_FILE,if=virtio,format=raw \\"
echo "      -nographic"
echo ""
echo "  Launch with U-Boot (real hardware):"
echo "    Flash U-Boot to BIOS chip, boot from disk"
echo "============================================"
echo ""
