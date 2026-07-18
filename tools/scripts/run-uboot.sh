#!/bin/bash
# Launch Strat9-OS with U-Boot
# For x86_64: uses OVMF (U-Boot is too large for QEMU BIOS area)
# For aarch64/riscv64: uses U-Boot as firmware

set -e

BUILD_DIR="build"
QEMU="${QEMU:-qemu-system-x86_64}"
ARCH="${STRAT9_ARCH:-x86_64}"
PROFILE="${STRAT9_PROFILE:-release}"
IMAGE="$BUILD_DIR/strat9-os.img"

case "$ARCH" in
    x86_64|x86)
        echo "Launching x86_64 with OVMF..."
        ${QEMU} \
            -machine q35 \
            -cpu qemu64 \
            -smp 4 \
            -m 2G \
            -bios /usr/share/ovmf/OVMF.fd \
            -drive file=${IMAGE},if=virtio,format=raw \
            -nographic \
            -no-reboot
        ;;
    aarch64|arm64)
        echo "Launching aarch64 with U-Boot firmware..."
        ${QEMU} \
            -machine virt \
            -cpu cortex-a72 \
            -smp 4 \
            -m 2G \
            -bios build/uboot/u-boot.bin \
            -drive file=${IMAGE},if=virtio,format=raw \
            -nographic \
            -no-reboot
        ;;
    riscv64|riscv)
        echo "Launching riscv64 with OpenSBI + U-Boot..."
        ${QEMU} \
            -machine virt \
            -smp 4 \
            -m 2G \
            -bios default \
            -kernel build/uboot/u-boot.bin \
            -drive file=${IMAGE},if=virtio,format=raw \
            -nographic \
            -no-reboot
        ;;
    *)
        echo "Unknown architecture: $ARCH"
        echo "Supported: x86_64, aarch64, riscv64"
        exit 1
        ;;
esac
