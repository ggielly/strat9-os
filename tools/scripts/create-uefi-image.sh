#!/usr/bin/env bash
# Build a GPT disk containing one 256 MiB FAT32 EFI System Partition.
# No compilation: consume and validate the selected build artifacts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/uefi-modules.sh"
source "$SCRIPT_DIR/uefi-image-common.sh"
BUILD_DIR="${STRAT9_BUILD_DIR:-build}"
IMAGE_BASENAME="${STRAT9_IMAGE_BASENAME:-strat9-os}"
PROFILE="${STRAT9_PROFILE:-debug}"
MODULE_PROFILE="${STRAT9_MODULE_PROFILE:-release}"
INCLUDE_TESTS="${STRAT9_INCLUDE_TESTS:-0}"
MODULE_MANIFEST="${STRAT9_MODULE_MANIFEST:-tools/uefi-modules.manifest}"
MODULE_TARGET_DIR="target/x86_64-unknown-none/$MODULE_PROFILE"
BOOTLOADER_EFI="target/x86_64-unknown-uefi/$PROFILE/strat9-bootloader.efi"
KERNEL_ELF="target/x86_64-unknown-none/$PROFILE/kernel"

strat9_image_name "$IMAGE_BASENAME"
case "$PROFILE:$MODULE_PROFILE" in
    debug:debug|debug:release|release:debug|release:release) ;;
    *) echo "ERROR: profiles must be debug or release" >&2; exit 1 ;;
esac
# Check the actual executables used, before touching staging or existing images.
strat9_require_tools parted mkfs.fat fsck.fat mcopy python3 dd cp mv cmp mkdir mktemp rm stat od cat
[[ -s "$BOOTLOADER_EFI" && -s "$KERNEL_ELF" ]] || {
    echo "ERROR: missing or empty loader/kernel for profile $PROFILE" >&2; exit 1;
}
strat9_validate_module_sources "$MODULE_TARGET_DIR" "$MODULE_MANIFEST" "$INCLUDE_TESTS"

strat9_start_image_work
IMAGE_FILE="$BUILD_DIR/$IMAGE_BASENAME-uefi.img"
PAYLOAD_DIR="$BUILD_DIR/$IMAGE_BASENAME-uefi-root"
ROOT="$IMAGE_WORK/payload"
DISK="$IMAGE_WORK/disk.img"
ESP="$IMAGE_WORK/esp.img"
[[ ! -d "$IMAGE_FILE" && ! -L "$PAYLOAD_DIR" ]] || {
    echo "ERROR: invalid image/staging destination" >&2; exit 1;
}
mkdir -p "$ROOT/efi/boot" "$ROOT/boot/initfs"
cp -- "$BOOTLOADER_EFI" "$ROOT/efi/boot/BOOTX64.EFI"
cp -- "$KERNEL_ELF" "$ROOT/boot/kernel.elf"
cp -- "$MODULE_MANIFEST" "$ROOT/modules.manifest"
printf '%s\n' "$INCLUDE_TESTS" > "$ROOT/include-tests"
strat9_copy_modules "$MODULE_TARGET_DIR" "$ROOT/boot/initfs"
strat9_check_payload "$ROOT"

SECTOR_SIZE=512
DISK_SECTORS=$((512 * 1024 * 1024 / SECTOR_SIZE))
ESP_START=2048
ESP_SECTORS=$((256 * 1024 * 1024 / SECTOR_SIZE))
ESP_END=$((ESP_START + ESP_SECTORS - 1)) # Inclusive GPT end: 526335.
dd if=/dev/zero of="$DISK" bs="$SECTOR_SIZE" count=0 seek="$DISK_SECTORS" status=none
parted -s "$DISK" mklabel gpt
parted -s "$DISK" unit s mkpart ESP fat32 "${ESP_START}s" "${ESP_END}s"
parted -s "$DISK" set 1 esp on
dd if=/dev/zero of="$ESP" bs="$SECTOR_SIZE" count=0 seek="$ESP_SECTORS" status=none
strat9_fill_and_check_fat "$ESP" "$ROOT" "$ESP_START" "$IMAGE_WORK/readback"
dd if="$ESP" of="$DISK" bs=1M seek=1 conv=notrunc status=none
python3 "$SCRIPT_DIR/validate-uefi-image.py" disk "$DISK" \
    --esp-start "$ESP_START" --esp-sectors "$ESP_SECTORS"

# Keep staging specific to this image name. Roll it back if final publication
# fails; the old disk remains intact until the final same-filesystem rename.
publish_cleanup() {
    local result=$?
    # The disk rename is the commit point, including if a signal arrives just
    # after mv. Infer progress from paths instead of interruptible shell flags.
    if [[ -e "$DISK" ]]; then
        if [[ ! -e "$ROOT" && -e "$PAYLOAD_DIR" ]]; then
            mv -T -- "$PAYLOAD_DIR" "$IMAGE_WORK/unpublished-payload" || return 1
        fi
        if [[ -e "$IMAGE_WORK/previous-payload" ]]; then
            # Keep the backup in IMAGE_WORK if restoration fails.
            mv -T -- "$IMAGE_WORK/previous-payload" "$PAYLOAD_DIR" || return 1
        fi
    fi
    strat9_clean_image_work
    return "$result"
}
trap publish_cleanup EXIT
if [[ -e "$PAYLOAD_DIR" ]]; then mv -T -- "$PAYLOAD_DIR" "$IMAGE_WORK/previous-payload"; fi
mv -T -- "$ROOT" "$PAYLOAD_DIR"
mv -fT -- "$DISK" "$IMAGE_FILE"
echo "[OK] UEFI image created and validated: $IMAGE_FILE ($(stat -c%s "$IMAGE_FILE") bytes)"
echo "     ESP: sectors $ESP_START..$ESP_END ($ESP_SECTORS sectors); modules: ${#STRAT9_MODULE_NAMES[@]}"
