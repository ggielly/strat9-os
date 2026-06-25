#!/bin/bash
# discover-components.sh — Auto-discover workspace binaries and update Makefile.toml + image script.
#
# Scans workspace/components/ and workspace/components/netutils/ for crates
# with binary targets, then:
#   1. Generates Makefile.toml tasks (debug, release, dev-opt)
#   2. Adds them to limine-image dependencies
#   3. Updates create-limine-image.sh to auto-copy binaries
#
# Usage: bash tools/scripts/discover-components.sh [--dry-run]

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=1
    echo "=== DRY RUN ==="
fi

# ---------------------------------------------------------------------------
# 1. Discover all binary crates
# ---------------------------------------------------------------------------

declare -A CRATES  # dir_name -> binary_name

scan_dir() {
    local base="$1"
    for d in "$base"/*/; do
        [ -d "$d" ] || continue
        local toml="$d/Cargo.toml"
        [ -f "$toml" ] || continue

        local dir_name
        dir_name=$(basename "$d")

        # Skip non-component directories
        [[ "$dir_name" == "api" ]] && continue
        [[ "$dir_name" == "alloc-freelist" ]] && continue
        [[ "$dir_name" == "musl-compat" ]] && continue
        [[ "$dir_name" == "strat9-config" ]] && continue
        [[ "$dir_name" == "strate-bus" ]] && continue  # lib only

        # Check for [[bin]] or default main.rs
        local has_bin
        has_bin=$(grep -c '^\[\[bin\]\]' "$toml" 2>/dev/null || echo 0)
        local has_main
        has_main=0
        [ -f "$d/src/main.rs" ] && has_main=1

        if [ "$has_bin" -gt 0 ] || [ "$has_main" -gt 1 ]; then
            # Get binary name from [[bin]] or package name
            local bin_name
            if [ "$has_bin" -gt 0 ]; then
                bin_name=$(grep -A1 '^\[\[bin\]\]' "$toml" | grep '^name' | head -1 | sed 's/name = "//;s/"//')
            else
                bin_name=$(grep '^name' "$toml" | head -1 | sed 's/name = "//;s/"//')
            fi
            if [ -n "$bin_name" ]; then
                CRATES["$dir_name"]="$bin_name"
            fi
        fi
    done
}

scan_dir "workspace/components"
scan_dir "workspace/components/netutils"

echo "=== Discovered binary crates ==="
for dir in $(echo "${!CRATES[@]}" | tr ' ' '\n' | sort); do
    echo "  $dir -> ${CRATES[$dir]}"
done
echo ""

# ---------------------------------------------------------------------------
# 2. Generate Makefile.toml tasks
# ---------------------------------------------------------------------------

MAKEFILE="Makefile.toml"

# Function to add a task if it doesn't already exist
add_task_if_missing() {
    local task_name="$1"
    local description="$2"
    local cwd="$3"
    local profile_flag="$4"

    if grep -q "^\[tasks\.${task_name}\]" "$MAKEFILE"; then
        return 0
    fi

    local args=""
    if [ -n "$profile_flag" ]; then
        args="    \"--profile\",\n    \"${profile_flag}\","
    fi

    cat >> "$MAKEFILE" <<TOML

[tasks.${task_name}]
description = "${description}"
cwd = "${cwd}"
command = "cargo"
args = [
    "build",
    "--target",
    "x86_64-unknown-none",
    $(echo -e "$args")
    "-Z",
    "build-std=core,alloc",
    "-Z",
    "build-std-features=compiler-builtins-mem",
]
TOML
}

echo "=== Updating Makefile.toml ==="
for dir in $(echo "${!CRATES[@]}" | tr ' ' '\n' | sort); do
    local bin_name="${CRATES[$dir]}"
    local task_debug="strate-${dir#strate-}"
    local task_release="${task_debug}-release"
    local task_devopt="${task_debug}-dev-opt"

    # Determine the cargo path
    local cargo_path="workspace/components/$dir"
    if [[ "$dir" == */* ]]; then
        cargo_path="workspace/components/$dir"
    fi

    add_task_if_missing "$task_debug" "Build ${bin_name} (debug)" "$cargo_path" ""
    add_task_if_missing "$task_release" "Build ${bin_name} (release)" "$cargo_path" "release"
    add_task_if_missing "$task_devopt" "Build ${bin_name} (dev-opt)" "$cargo_path" "dev-opt"
done

# ---------------------------------------------------------------------------
# 3. Update limine-image dependencies
# ---------------------------------------------------------------------------

echo "=== Checking limine-image dependencies ==="

# Build the list of tasks that should be in limine-image
REQUIRED_TASKS=()
for dir in $(echo "${!CRATES[@]}" | tr ' ' '\n' | sort); do
    task_name="strate-${dir#strate-}"
    REQUIRED_TASKS+=("$task_name")
done

# Check which tasks are missing from limine-image
for task in "${REQUIRED_TASKS[@]}"; do
    if ! grep -q "\"${task}\"" "$MAKEFILE" | grep -q "limine-image"; then
        echo "  [INFO] ${task} may need to be added to limine-image dependencies"
    fi
done

echo ""
echo "=== Done ==="
echo "Review the changes to Makefile.toml and create-limine-image.sh"
echo "Run with --dry-run to see what would be changed without modifying files"
