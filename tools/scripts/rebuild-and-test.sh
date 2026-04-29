#!/bin/bash

# Script pour rebuild et tester strat9-os

set -e

# Kill all QEMU processes
echo "Killing all QEMU processes..."
pkill -f qemu 2>/dev/null || true
sleep 2

# Reassemble stage2
echo "Assembling stage2..."
nasm -f bin -Ibootloader/asm/x86_64/ -o build/stage2.bin bootloader/asm/x86_64/stage2.asm
if [ $? -ne 0 ]; then
    echo "NASM error!"
    exit 1
fi
stage2_size=$(stat -c%s build/stage2.bin)
echo "  stage2.bin: $stage2_size bytes"

# Delete old image
rm -f "build/strat9-os.img"

# Create new image
echo "Creating disk image..."
# Assuming create-disk-image.sh exists, but since it's legacy, maybe call create-image.sh
# The original calls create-disk-image.ps1, but we have create-image.sh
bash tools/scripts/create-image.sh >/dev/null 2>&1

if [ ! -f "build/strat9-os.img" ]; then
    echo "Failed to create image!"
    exit 1
fi

image_size=$(stat -c%s build/strat9-os.img)
echo "Image created: $image_size bytes"
echo ""
echo "Launching QEMU (press Ctrl+C to stop)..."
echo "========================================="

# Launch QEMU
qemu-system-x86_64 \
    -drive "format=raw,file=build/strat9-os.img" \
    -machine q35 \
    -m 256M \
    -serial stdio \
    -nographic \
    -no-reboot