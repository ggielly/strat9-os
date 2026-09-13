#!/bin/bash
# Source-only helpers: select and validate every module before image staging.
# No directory scanning, image creation, partitioning or compilation here.

strat9_read_module_manifest() {
    local manifest="$1" include_tests="$2"
    local group name producer extra previous has_init=0
    local LC_ALL=C
    STRAT9_MODULE_NAMES=()
    case "$include_tests" in 0|1) ;; *) echo "ERROR: STRAT9_INCLUDE_TESTS must be 0 or 1" >&2; return 1 ;; esac
    if [ ! -r "$manifest" ]; then
        echo "ERROR: module manifest not readable: $manifest" >&2
        return 1
    fi
    while read -r group name producer extra || [ -n "$group" ]; do
        case "$group" in ""|\#*) continue ;; base|test) ;; *)
            echo "ERROR: invalid manifest group: $group" >&2; return 1 ;;
        esac
        if [ -z "$producer" ] || [ -n "$extra" ] || [ "${#name}" -gt 63 ] ||
            [[ ! "$name" =~ ^[a-zA-Z0-9._-]+$ ]] || [[ "$name" == *. ]]; then
            echo "ERROR: invalid module manifest entry: $group $name $producer $extra" >&2
            return 1
        fi
        if [ "$group" = test ] && [ "$include_tests" = 0 ]; then continue; fi
        for previous in "${STRAT9_MODULE_NAMES[@]}"; do
            if [ "${previous,,}" = "${name,,}" ]; then
                echo "ERROR: duplicate module filename: $name" >&2
                return 1
            fi
        done
        STRAT9_MODULE_NAMES+=("$name")
        case "$name" in init|strate-init) has_init=1 ;; esac
    done < "$manifest"
    if [ "$has_init" = 0 ] || [ "${#STRAT9_MODULE_NAMES[@]}" -gt 64 ]; then
        echo "ERROR: module manifest requires init/strate-init and at most 64 files" >&2
        return 1
    fi
}

strat9_validate_module_sources() {
    local target_dir="$1" manifest="$2" include_tests="$3"
    local name source magic
    strat9_read_module_manifest "$manifest" "$include_tests" || return 1
    for name in "${STRAT9_MODULE_NAMES[@]}"; do
        source="$target_dir/$name"
        if [ ! -f "$source" ] || [ ! -s "$source" ]; then
            echo "ERROR: required module missing or empty: $source" >&2
            return 1
        fi
        magic=$(od -An -tx1 -N6 "$source") || {
            echo "ERROR: cannot read module ELF header: $source" >&2
            return 1
        }
        # ELF64, little endian. The kernel's ELF loader validates the full image.
        if [[ ! "$magic" =~ ^[[:space:]]*7f[[:space:]]+45[[:space:]]+4c[[:space:]]+46[[:space:]]+02[[:space:]]+01[[:space:]]*$ ]]; then
            echo "ERROR: required module is not ELF64 little-endian: $source" >&2
            return 1
        fi
    done
}

strat9_copy_modules() {
    local target_dir="$1" destination="$2"
    local name
    for name in "${STRAT9_MODULE_NAMES[@]}"; do
        cp -- "$target_dir/$name" "$destination/$name" || return 1
        echo "  [OK] Module: $name ($target_dir)"
    done
}
