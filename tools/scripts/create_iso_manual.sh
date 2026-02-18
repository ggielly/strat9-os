#!/bin/bash

BUILD_DIR="build"
ISO_ROOT="$BUILD_DIR/iso_root"

# Run xorriso to create the ISO
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
    -o "$BUILD_DIR/strat9-os.iso"

# Install Limine to the ISO
"$BUILD_DIR/limine/limine" bios-install "$BUILD_DIR/strat9-os.iso"

echo "ISO creation completed."