#!/usr/bin/env bash
# =============================================================================
# build-selftest-iso.sh : build the UEFI selftest ISO (no Limine), option A.
#
# Produces: build/strat9-os-selftest-uefi.iso
# Chain: kernel --features selftest + bootloader-uefi + userspace components
#        -> create-uefi-image.sh -> create-iso-uefi.sh
#
# Usage:
#   tools/ci/build-selftest-iso.sh [--profile debug|release] [--skip-build]
#
# CI: called by the `build-selftest-iso` GitLab job on the strat9-builder VM.
#     Local dev: `cargo make selftest-iso-uefi` does the same via cargo-make.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PROFILE="debug"
SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)    PROFILE="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help)    grep '^#' "$0" | head -20; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

ISO="build/strat9-os-selftest-uefi.iso"

if [[ $SKIP_BUILD -eq 1 && -f "$ISO" ]]; then
    echo "==> Reusing existing $ISO (--skip-build)"
    ls -lh "$ISO"
    exit 0
fi

export STRAT9_IMAGE_BASENAME="strat9-os-selftest"
export STRAT9_PROFILE="$PROFILE"
export STRAT9_INCLUDE_TESTS="1"

echo "==> Building selftest UEFI ISO (profile=$PROFILE)"

if ! command -v cargo-make >/dev/null 2>&1 && ! cargo make --version >/dev/null 2>&1; then
    echo "ERROR: cargo-make not found. Install with: cargo install cargo-make" >&2
    exit 2
fi

cargo make selftest-iso-uefi

if [[ ! -f "$ISO" ]]; then
    echo "ERROR: expected ISO not produced: $ISO" >&2
    exit 1
fi

echo ""
echo "==> OK: $ISO"
ls -lh "$ISO"
sha256sum "$ISO" | tee "build/strat9-os-selftest-uefi.iso.sha256"
