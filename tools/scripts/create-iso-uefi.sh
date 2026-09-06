#!/bin/bash
# Create a UEFI-bootable ISO using our own strat9-bootloader.efi (no Limine).
# The ISO embeds a FAT EFI boot image (El Torito) containing:
#   /efi/boot/bootx64.efi - our UEFI loader
#   /boot/kernel.elf      - the kernel ELF
#   /boot/initfs/*        - userspace modules
# Requires: mtools (mcopy), dosfstools (mkfs.fat), xorriso.
# Expects build/uefi_iso_root already populated (run create-uefi-image.sh first
# or depend on the uefi-image cargo-make task).

set -e

BUILD_DIR="build"
ESP_SRC="$BUILD_DIR/uefi_iso_root"
EFIBOOT_IMG="$BUILD_DIR/efiboot.img"
ISO_STAGING="$BUILD_DIR/iso_uefi_root"
ISO_BASENAME="${STRAT9_IMAGE_BASENAME:-strat9-os}"
ISO_FILE="$BUILD_DIR/${ISO_BASENAME}-uefi.iso"

echo ""
echo "=== Creating UEFI-bootable ISO (own loader, no Limine) ==="
echo ""

if [ ! -f "$ESP_SRC/efi/boot/BOOTX64.EFI" ]; then
    echo "ERROR: UEFI loader not found at $ESP_SRC/efi/boot/BOOTX64.EFI"
    echo "  Build with: cargo make uefi-image (or uefi-image-release)"
    exit 1
fi
if [ ! -f "$ESP_SRC/boot/kernel.elf" ]; then
    echo "ERROR: kernel not found at $ESP_SRC/boot/kernel.elf"
    echo "  Build with: cargo make uefi-image (or uefi-image-release)"
    exit 1
fi

for tool in mcopy mkfs.fat xorriso; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool '$tool' not found"
        exit 1
    fi
done

# Size the FAT EFI boot image from the actual payload plus headroom.
payload_mb=$(du -sm "$ESP_SRC" | cut -f1)
EFIBOOT_MB=$((payload_mb + 16))
[ "$EFIBOOT_MB" -lt 32 ] && EFIBOOT_MB=32
echo "  Payload     : ~${payload_mb} MB -> efiboot.img ${EFIBOOT_MB} MB"

SECTORS=$((EFIBOOT_MB * 1024 * 1024 / 512))
rm -f "$EFIBOOT_IMG"
dd if=/dev/zero of="$EFIBOOT_IMG" bs=512 count=$SECTORS 2>/dev/null
mkfs.fat -F 32 -n "EFIBOOT" "$EFIBOOT_IMG" 2>/dev/null

mcopy -i "$EFIBOOT_IMG" -s "$ESP_SRC/efi" "::/efi"
mcopy -i "$EFIBOOT_IMG" -s "$ESP_SRC/boot" "::/boot"
echo "  [OK] EFI boot image: $EFIBOOT_IMG"

# ISO staging holds only the EFI boot image (the loader reads
# kernel + initfs from this FAT image once booted).
rm -rf "$ISO_STAGING"
mkdir -p "$ISO_STAGING"
cp "$EFIBOOT_IMG" "$ISO_STAGING/efiboot.img"

rm -f "$ISO_FILE"
xorriso -as mkisofs \
    -o "$ISO_FILE" \
    --efi-boot efiboot.img \
    -efi-boot-part \
    --efi-boot-image \
    --protective-msdos-label \
    "$ISO_STAGING" 2>&1 | tail -5

echo ""
echo "  [OK] UEFI ISO: $ISO_FILE"
ls -lh "$ISO_FILE"
file "$ISO_FILE" | head -c 200
echo ""
