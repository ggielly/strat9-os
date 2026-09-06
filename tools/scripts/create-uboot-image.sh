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

# Create FAT32 partition image
FAT_IMG="$BUILD_DIR/fat32.img"
dd if=/dev/zero of="$FAT_IMG" bs=1M count=63 2>/dev/null
mkfs.vfat -F 32 "$FAT_IMG" >/dev/null

# Create directory structure in FAT32 image
echo "  --- Populating boot partition ---"
mmd -i "$FAT_IMG" ::EFI
mmd -i "$FAT_IMG" ::EFI/BOOT
mmd -i "$FAT_IMG" ::boot
mmd -i "$FAT_IMG" ::modules
mmd -i "$FAT_IMG" ::modules/bin

# Copy kernel
mcopy -i "$FAT_IMG" "$KERNEL_ELF" ::boot/kernel.elf
echo "  [OK] kernel.elf"

# Copy U-Boot as EFI payload (not app)
# When built as EFI payload, the binary is at u-boot-payload.efi and is loaded
# via the OVMF UI or startup.nsh. U-Boot then takes full hardware control.
if [ -f "$BUILD_DIR/uboot/u-boot-payload.efi" ]; then
    mcopy -i "$FAT_IMG" "$BUILD_DIR/uboot/u-boot-payload.efi" ::EFI/BOOT/BOOTX64.EFI
    echo "  [OK] U-Boot EFI payload (BOOTX64.EFI)"
elif [ -f "$BUILD_DIR/uboot/u-boot.efi" ]; then
    mcopy -i "$FAT_IMG" "$BUILD_DIR/uboot/u-boot.efi" ::EFI/BOOT/BOOTX64.EFI
    echo "  [OK] U-Boot EFI payload (u-boot.efi)"
fi

# Create U-Boot boot script that loads the kernel + DTB
#
# Flow:
#   1. Load kernel ELF from FAT partition into RAM
#   2. Generate or load a FDT (device tree) describing memory map
#   3. bootm loads the ELF and passes the DTB to the kernel
#
cat > /tmp/boot.scr << 'SCRIPT_EOF'
# Strat9-OS U-Boot boot script
#
# U-Boot conventions:
#   ${kernel_addr_r}  : where to load the kernel ELF
#   ${fdt_addr_r}     : where to place the device tree
#   ${ramdisk_addr_r} : (unused : no initramfs)

setenv bootargs "console=ttyS0,115200"

# Load kernel ELF from FAT partition (first partition = 0:1)
load virtio 0:1 ${kernel_addr_r} /boot/kernel.elf

# Generate a minimal device tree for the kernel.
# U-Boot can synthesise one from the EFI memory map.
# Fallback: use the built-in EFI payload DTB.
fdt addr ${fdt_addr_r} || fdt addr ${fdtcontroladdr}

# Boot the kernel ELF : passes DTB pointer in RDI.
# The bootm command reads the ELF header, loads segments,
# parses the FDT, and jumps to the entry point.
#
# Syntax: bootm [kernel_addr] [initrd_addr] [fdt_addr]
# initrd_addr = - (none), fdt_addr = ${fdt_addr_r}
bootm ${kernel_addr_r} - ${fdt_addr_r}
SCRIPT_EOF

# Compile the script with mkimage (U-Boot tool)
mkimage -C none -A x86_64 -T script -d /tmp/boot.scr /tmp/boot.scr.uimg 2>/dev/null || \
    echo "  [WARN] mkimage not found : boot script not compiled"

if [ -f /tmp/boot.scr.uimg ]; then
    mcopy -i "$FAT_IMG" /tmp/boot.scr.uimg ::boot.scr.uimg
    echo "  [OK] U-Boot boot script (boot.scr.uimg)"
fi
rm -f /tmp/boot.scr /tmp/boot.scr.uimg

# Set fallback bootcmd in U-Boot environment
# When no boot script is found, U-Boot will use this:
cat > /tmp/uboot-env.txt << 'ENV_EOF'
bootcmd=load virtio 0:1 ${kernel_addr_r} /boot/kernel.elf && fdt addr ${fdtcontroladdr} && bootm ${kernel_addr_r} - ${fdt_addr_r}
bootdelay=2
ENV_EOF
mcopy -i "$FAT_IMG" /tmp/uboot-env.txt ::uboot-env.txt 2>/dev/null || true
rm -f /tmp/uboot-env.txt

echo "  [OK] U-Boot boot script + environment"

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
    if [ -f "$src_file" ]; then
        mcopy -i "$FAT_IMG" "$src_file" "::modules/$dst_path"
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
        # Skip if already copied
        mdir -i "$FAT_IMG" "::modules/$name" >/dev/null 2>&1 && continue
        if file "$elf" 2>/dev/null | grep -q "ELF"; then
            mcopy -i "$FAT_IMG" "$elf" "::modules/$name"
            echo "  [OK] Auto-copied: /modules/$name"
        fi
    done
fi

# Copy config files
for f in workspace/assets/boot/silo.toml workspace/assets/boot/kernel.toml; do
    if [ -f "$f" ]; then
        mcopy -i "$FAT_IMG" "$f" "::modules/$(basename "$f")"
        echo "  [OK] Copied $(basename "$f")"
    fi
done

# Copy WASM files
for f in workspace/assets/wasm/hello.wasm workspace/assets/wasm/wasm-test.toml; do
    if [ -f "$f" ]; then
        mcopy -i "$FAT_IMG" "$f" "::modules/$(basename "$f")"
        echo "  [OK] Copied $(basename "$f")"
    fi
done

echo ""

# Write FAT32 to disk
echo "  --- Writing partition data ---"
dd if="$FAT_IMG" of="$IMAGE_FILE" bs=512 seek=2048 conv=notrunc 2>/dev/null
echo "  [OK] FAT32 boot partition written"

# Cleanup
rm -f "$FAT_IMG"

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
