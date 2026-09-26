#!/usr/bin/env bash
# Build and validate an El Torito UEFI ISO from the matching image's staging.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/uefi-modules.sh"
source "$SCRIPT_DIR/uefi-image-common.sh"
BUILD_DIR="${STRAT9_BUILD_DIR:-build}"
IMAGE_BASENAME="${STRAT9_IMAGE_BASENAME:-strat9-os}"
strat9_image_name "$IMAGE_BASENAME"
strat9_require_tools mcopy mkfs.fat fsck.fat xorriso python3 dd du cut cp mv cmp mkdir mktemp rm cat od stat
ESP_SRC="$BUILD_DIR/$IMAGE_BASENAME-uefi-root"
strat9_check_payload "$ESP_SRC"

strat9_start_image_work
ESP_SRC="$BUILD_DIR/$IMAGE_BASENAME-uefi-root"
ISO_FILE="$BUILD_DIR/$IMAGE_BASENAME-uefi.iso"
[[ ! -d "$ISO_FILE" ]] || { echo "ERROR: ISO destination is a directory" >&2; exit 1; }
ISO_STAGING="$IMAGE_WORK/iso-root"
mkdir -p "$ISO_STAGING"
EFIBOOT_IMG="$ISO_STAGING/efiboot.img"
# At least 64 MiB and one sector per cluster: stay above FAT32's minimum
# cluster count even for a tiny payload. Include space for FATs and directories.
payload_mb=$(du --apparent-size -sm "$ESP_SRC" | cut -f1)
EFIBOOT_MB=$((payload_mb + payload_mb / 16 + 16))
if (( EFIBOOT_MB < 64 )); then EFIBOOT_MB=64; fi
dd if=/dev/zero of="$EFIBOOT_IMG" bs=1M count=0 seek="$EFIBOOT_MB" status=none
strat9_fill_and_check_fat "$EFIBOOT_IMG" "$ESP_SRC" 0 "$IMAGE_WORK/readback"
python3 "$SCRIPT_DIR/validate-uefi-image.py" fat "$EFIBOOT_IMG"

ISO_TMP="$IMAGE_WORK/output.iso"
# No pipeline can hide the producer's status. xorriso aborts on FAILURE.
xorriso -abort_on FAILURE -as mkisofs \
    -R -o "$ISO_TMP" --efi-boot efiboot.img -efi-boot-part \
    --efi-boot-image --protective-msdos-label "$ISO_STAGING"
[[ -s "$ISO_TMP" ]] || { echo "ERROR: xorriso produced no ISO" >&2; exit 1; }
# Reopen the output, require a UEFI no-emulation boot entry, and compare the
# embedded FAT payload byte-for-byte with the one validated above.
xorriso -abort_on FAILURE -indev "$ISO_TMP" -report_el_torito plain \
    > "$IMAGE_WORK/el-torito.txt" 2>&1
python3 "$SCRIPT_DIR/validate-uefi-iso-report.py" "$IMAGE_WORK/el-torito.txt"
xorriso -abort_on FAILURE -osirrox on -indev "$ISO_TMP" \
    -extract /efiboot.img "$IMAGE_WORK/extracted-efiboot.img"
cmp -- "$EFIBOOT_IMG" "$IMAGE_WORK/extracted-efiboot.img"
mv -fT -- "$ISO_TMP" "$ISO_FILE"
echo "[OK] UEFI ISO created and validated: $ISO_FILE ($(stat -c%s "$ISO_FILE") bytes)"
