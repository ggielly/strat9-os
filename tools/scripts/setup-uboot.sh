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
        # x86_64: U-Boot as EFI app, loaded by OVMF
        echo "Building U-Boot for x86_64 (EFI app)..."
        make qemu-x86_64_defconfig
        
        # Enable EFI boot support (for loading as EFI app)
        scripts/config --enable CONFIG_EFI_LOADER
        scripts/config --enable CONFIG_CMD_BOOTEFI
        scripts/config --enable CONFIG_EFI_BINARY_EXEC
        scripts/config --enable CONFIG_EFI_GET_TIME
        scripts/config --enable CONFIG_EFI_HAVE_RUNTIME_RESET
        
        # Enable FAT filesystem for boot partition
        scripts/config --enable CONFIG_FS_FAT
        scripts/config --enable CONFIG_CMD_FAT
        scripts/config --enable CONFIG_CMD_LS
        scripts/config --enable CONFIG_CMD_LOAD
        
        # Enable ELF loading
        scripts/config --enable CONFIG_CMD_ELF
        
        # Enable serial console
        scripts/config --enable CONFIG_SERIAL
        scripts/config --enable CONFIG_SYS_NS16550
        
        make olddefconfig
        make -j$(nproc)
        
        echo ""
        echo "U-Boot built for x86_64 (EFI app)"
        echo "  Binary: $UBOOT_DIR/u-boot"
        echo "  Use with OVMF: qemu-system-x86_64 -bios /usr/share/ovmf/OVMF.fd ..."
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
