#!/bin/bash
# Setup U-Boot for Strat9-OS
# For x86_64: builds U-Boot as EFI application (loaded by OVMF)
# For aarch64/riscv64: builds U-Boot as firmware

set -e

BUILD_DIR="build"
UBOOT_DIR="$BUILD_DIR/uboot"
ARCH="${1:-x86_64}"

echo "=== Setting up U-Boot for Strat9-OS ($ARCH) ==="

# Clone U-Boot if not present
if [ ! -d "$UBOOT_DIR" ]; then
    echo "Cloning U-Boot using Github..."
    mkdir -p "$BUILD_DIR"
    git clone https://github.com/u-boot/u-boot.git "$UBOOT_DIR"
    cd "$UBOOT_DIR" && git checkout v2026.07 && cd -
fi

cd "$UBOOT_DIR"

case "$ARCH" in
    x86_64|x86)
        # x86_64: U-Boot as EFI PAYLOAD (not app).
        # A UEFI payload takes full hardware control, unlike an EFI app which
        # remains a guest of the UEFI firmware. The payload is loaded by OVMF
        # (via a special UEFI image) and then runs natively — owns interrupts,
        # PCI, DMA, IOMMU, everything the Strat9 kernel needs.
        echo "Building U-Boot for x86_64 (EFI payload)..."
        make efi-x86_payload64_defconfig
        
        # Enable FAT filesystem for boot partition (where kernel + modules live)
        scripts/config --enable CONFIG_FS_FAT
        scripts/config --enable CONFIG_CMD_FAT
        scripts/config --enable CONFIG_CMD_LS
        scripts/config --enable CONFIG_CMD_LOAD
        
        # Enable ELF loading (Strat9 kernel is a raw ELF)
        scripts/config --enable CONFIG_CMD_ELF
        scripts/config --enable CONFIG_CMD_BOOTM
        scripts/config --enable CONFIG_CMD_BOOTEFI
        
        # Enable FDT support — Strat9 kernel receives DTB pointer in RDI
        scripts/config --enable CONFIG_OF_LIBFDT
        scripts/config --enable CONFIG_OF_BOARD_SETUP
        scripts/config --enable CONFIG_CMD_FDT
        
        # Enable serial console
        scripts/config --enable CONFIG_SERIAL
        scripts/config --enable CONFIG_SYS_NS16550
        
        # Enable bdinfo for debugging memory map
        scripts/config --enable CONFIG_CMD_BDI
        
        make olddefconfig
        make -j$(nproc)
        
        echo ""
        echo "U-Boot built for x86_64 (EFI payload)"
        echo "  Binary: $UBOOT_DIR/u-boot-payload.efi"
        echo "  This is loaded by OVMF as a UEFI payload."
        echo "  U-Boot then owns the hardware and loads the kernel ELF via bootm."
        ;;
        
    aarch64|arm64)
        # aarch64: U-Boot as firmware
        echo "Building U-Boot for aarch64 (firmware)..."
        make qemu_arm64_defconfig
        make -j$(nproc)
        
        echo ""
        echo "U-Boot built for aarch64 (firmware)"
        echo "  Binary: $UBOOT_DIR/u-boot.bin"
        echo "  Use: qemu-system-aarch64 -bios u-boot.bin ..."
        ;;
        
    riscv64|riscv)
        # riscv64: U-Boot as payload for OpenSBI
        echo "Building U-Boot for riscv64 (payload for OpenSBI)..."
        make qemu-riscv64_smode_defconfig
        make -j$(nproc)
        
        echo ""
        echo "U-Boot built for riscv64 (OpenSBI payload)"
        echo "  Binary: $UBOOT_DIR/u-boot.bin"
        echo "  Use: qemu-system-riscv64 -bios default -kernel u-boot.bin ..."
        ;;
        
    *)
        echo "ERROR: Unknown architecture: $ARCH"
        echo "Supported: x86_64, aarch64, riscv64"
        exit 1
        ;;
esac

cd - > /dev/null
echo ""
echo "=== U-Boot setup complete ==="
