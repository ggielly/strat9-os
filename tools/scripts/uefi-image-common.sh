#!/usr/bin/env bash
# Source-only helpers shared by the GPT and El Torito image producers.

strat9_require_tools() {
    local tool missing=0
    for tool in "$@"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "ERROR: required tool '$tool' not found" >&2
            missing=1
        fi
    done
    [[ "$missing" == 0 ]]
}

strat9_image_name() {
    [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]] || {
        echo "ERROR: invalid STRAT9_IMAGE_BASENAME: $1" >&2; return 1;
    }
}

# Delete only our mktemp directory directly inside the resolved build directory.
strat9_clean_image_work() {
    if [[ -n "${IMAGE_WORK:-}" && -d "$IMAGE_WORK" ]]; then
        local resolved
        resolved="$(cd "$IMAGE_WORK" && pwd -P)" || return 1
        [[ "${resolved%/*}" == "$BUILD_DIR" && "${resolved##*/}" == .uefi-work.* ]] || {
            echo "ERROR: refusing cleanup outside the image work directory" >&2; return 1;
        }
        rm -rf -- "$resolved"
    fi
}

strat9_start_image_work() {
    mkdir -p -- "$BUILD_DIR"
    BUILD_DIR="$(cd "$BUILD_DIR" && pwd -P)"
    IMAGE_WORK="$(mktemp -d "$BUILD_DIR/.uefi-work.XXXXXXXX")"
    trap strat9_clean_image_work EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

strat9_check_payload() {
    local root="$1"
    [[ -s "$root/boot/initfs/silo.toml" ]] || {
        echo "ERROR: missing or empty silo configuration in $root" >&2; return 1;
    }
    [[ -s "$root/efi/boot/BOOTX64.EFI" && -s "$root/boot/kernel.elf" ]] || {
        echo "ERROR: missing or empty EFI loader/kernel in $root" >&2; return 1;
    }
    # Read the exact manifest snapshot selected during disk-image staging.
    strat9_validate_module_sources "$root/boot/initfs" "$root/modules.manifest" "$(cat "$root/include-tests")"
}

strat9_fill_and_check_fat() {
    local fat="$1" root="$2" hidden="$3" readback="$4" name
    mkfs.fat -F 32 -S 512 -s 1 -h "$hidden" -n EFI "$fat"
    mcopy -i "$fat" -s "$root/efi" ::/efi
    mcopy -i "$fat" -s "$root/boot" ::/boot
    fsck.fat -n "$fat"
    # Reading every required file back detects truncated copies and filesystem
    # errors; compare bytes before publishing any image.
    mkdir -p -- "$readback"
    mcopy -i "$fat" -s ::/efi "$readback/"
    mcopy -i "$fat" -s ::/boot "$readback/"
    cmp -- "$root/efi/boot/BOOTX64.EFI" "$readback/efi/boot/BOOTX64.EFI"
    cmp -- "$root/boot/kernel.elf" "$readback/boot/kernel.elf"
    cmp -- "$root/boot/initfs/silo.toml" "$readback/boot/initfs/silo.toml"
    for name in "${STRAT9_MODULE_NAMES[@]}"; do
        cmp -- "$root/boot/initfs/$name" "$readback/boot/initfs/$name"
    done
}
