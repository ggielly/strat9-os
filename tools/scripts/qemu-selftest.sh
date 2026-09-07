#!/usr/bin/env bash
# =============================================================================
# qemu-selftest.sh : L3/L4 automated kernel selftest harness (anti-regression)
#
# Boots the Strat9 kernel (built with the `selftest` feature) under QEMU,
# captures the serial output, and reports PASS/FAIL mechanically.
#
# Boot path: UEFI ISO built WITHOUT Limine (own strat9-bootloader.efi):
#   cargo make selftest-iso-uefi
#   -> build/strat9-os-selftest-uefi.iso
#
# Exit codes: 0 = all selftests passed, 1 = at least one failure or timeout,
#             2 = usage / environment error.
#
# Usage:
#   tools/scripts/qemu-selftest.sh [--iso PATH] [--image PATH] [--timeout SECS]
#                                  [--skip-build] [--smp N] [--mem MB]
#                                  [--ovmf-code PATH] [--ovmf-vars PATH]
#
# CI (option A): designed for the `strat9-builder` VM on Proxmox
# (https://192.168.1.235:8006) with qemu-system-x86_64 + OVMF + KVM.
# Each pipeline boots an EPHEMERAL QEMU process (killed on exit via trap).
# See docs-site/src/testing-architecture.md (layers L3/L4).
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Preferred image: UEFI selftest ISO (no Limine). Legacy fallbacks kept for
# local dev machines that still have an old build lying around.
DEFAULT_ISO="build/strat9-os-selftest-uefi.iso"
TIMEOUT=180
SKIP_BUILD=0
SMP=2
MEM_MB=1024
QEMU="${QEMU:-qemu-system-x86_64}"
LOG="build/qemu-selftest.log"
MARKER_DONE="[selftest] orchestrator done"
ISO=""
# OVMF layout differs per distro (Debian: /usr/share/OVMF,
# Arch: /usr/share/edk2-ovmf/x64). Probe candidates unless overridden by env.
resolve_ovmf() {
    local kind="$1"       # CODE or VARS
    local override="$2"   # $OVMF_CODE / $OVMF_VARS if set
    local candidates=()
    if [[ "$kind" == "CODE" ]]; then
        candidates=(/usr/share/OVMF/OVMF_CODE_4M.fd
                    /usr/share/edk2-ovmf/x64/OVMF_CODE_4M.fd
                    /usr/share/edk2-ovmf/x64/OVMF_CODE.fd)
    else
        candidates=(/usr/share/OVMF/OVMF_VARS_4M.fd
                    /usr/share/edk2-ovmf/x64/OVMF_VARS_4M.fd
                    /usr/share/edk2-ovmf/x64/OVMF_VARS.fd)
    fi
    if [[ -n "$override" ]]; then
        echo "$override"
        return
    fi
    for c in "${candidates[@]}"; do
        if [[ -f "$c" ]]; then echo "$c"; return; fi
    done
    # Last resort: distro moved the firmware elsewhere (e.g. /usr/share/edk2/).
    if [[ "$kind" == "CODE" ]]; then
        find /usr/share -name 'OVMF_CODE*.fd' 2>/dev/null | sort | head -1 || true
    else
        find /usr/share -name 'OVMF_VARS*.fd' 2>/dev/null | sort | head -1 || true
    fi
}
OVMF_CODE="$(resolve_ovmf CODE "${OVMF_CODE:-}")"
OVMF_VARS_SRC="$(resolve_ovmf VARS "${OVMF_VARS:-}")"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iso|--image)    ISO="$2"; shift 2 ;;
        --timeout)        TIMEOUT="$2"; shift 2 ;;
        --skip-build)     SKIP_BUILD=1; shift ;;
        --smp)            SMP="$2"; shift 2 ;;
        --mem)            MEM_MB="$2"; shift 2 ;;
        --ovmf-code)      OVMF_CODE="$2"; shift 2 ;;
        --ovmf-vars)      OVMF_VARS_SRC="$2"; shift 2 ;;
        -h|--help)        grep '^#' "$0" | head -30; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

command -v "$QEMU" >/dev/null || { echo "ERROR: $QEMU not found" >&2; exit 2; }

# -----------------------------------------------------------------------------
# 1. Resolve boot image (explicit --iso wins, then selftest UEFI ISO, then
#    legacy fallbacks for backward compatibility with local builds).
# -----------------------------------------------------------------------------
if [[ -z "$ISO" ]]; then
    for candidate in "$DEFAULT_ISO" "build/strat9-os-selftest.iso" \
                     "build/strat9-os-uefi.iso" "build/strat9-os.iso"; do
        if [[ -f "$candidate" ]]; then
            ISO="$candidate"
            break
        fi
    done
fi

if [[ -z "$ISO" || ! -f "$ISO" ]]; then
    if [[ $SKIP_BUILD -eq 0 ]]; then
        echo "==> No bootable image found, building selftest UEFI ISO"
        echo "    (cargo make selftest-iso-uefi)"
        if ! cargo make selftest-iso-uefi; then
            echo "SELFTEST-HARNESS RESULT: BUILD-FAILED"
            exit 1
        fi
        ISO="$DEFAULT_ISO"
    fi
fi

if [[ ! -f "${ISO:-}" ]]; then
    echo "ERROR: no bootable image (tried $DEFAULT_ISO and legacy fallbacks)." >&2
    echo "  Build with: cargo make selftest-iso-uefi" >&2
    exit 2
fi
echo "==> Image: $ISO"

# -----------------------------------------------------------------------------
# 2. OVMF firmware (required for the UEFI ISO path). Copy VARS to a temp file
#    so concurrent CI jobs never share writable firmware state.
# -----------------------------------------------------------------------------
OVMF_VARS_TMP=""
if [[ "$ISO" == *.iso ]]; then
    if [[ ! -f "$OVMF_CODE" ]]; then
        echo "ERROR: OVMF code not found at $OVMF_CODE" >&2
        echo "  Install with: sudo apt install ovmf" >&2
        exit 2
    fi
    if [[ ! -f "$OVMF_VARS_SRC" ]]; then
        echo "ERROR: OVMF vars template not found at $OVMF_VARS_SRC" >&2
        exit 2
    fi
    OVMF_VARS_TMP="$(mktemp /tmp/strat9-ovmf-vars-XXXXXX.fd)"
    cp "$OVMF_VARS_SRC" "$OVMF_VARS_TMP"
    echo "==> OVMF: code=$OVMF_CODE vars(tmp)=$OVMF_VARS_TMP"
fi

# -----------------------------------------------------------------------------
# 3. Boot QEMU headless (ephemeral process), capture serial, stop on marker.
# -----------------------------------------------------------------------------
echo "==> Booting $ISO (timeout ${TIMEOUT}s, smp=${SMP}, mem=${MEM_MB}M)"
rm -f "$LOG"; : > "$LOG"

QEMU_ARGS=(
    -machine q35
    -cpu qemu64
    -smp "$SMP"
    -m "${MEM_MB}M"
    -serial "file:$LOG"
    -display none
    -no-reboot
    -no-shutdown
)
if [[ -n "$OVMF_VARS_TMP" ]]; then
    QEMU_ARGS+=(
        -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE"
        -drive "if=pflash,format=raw,file=$OVMF_VARS_TMP"
        -cdrom "$ISO"
    )
else
    # Legacy raw .img path (no OVMF): boot from disk image directly.
    QEMU_ARGS+=(-drive "file=$ISO,format=raw")
fi

"$QEMU" "${QEMU_ARGS[@]}" &
QEMU_PID=$!

cleanup() {
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
    [[ -n "$OVMF_VARS_TMP" ]] && rm -f "$OVMF_VARS_TMP"
}
trap cleanup EXIT

# Poll for the completion marker instead of a blind sleep: exits as soon as
# the orchestrator is done, fails after TIMEOUT seconds.
ELAPSED=0
INTERVAL=2
while kill -0 "$QEMU_PID" 2>/dev/null; do
    if grep -qF "$MARKER_DONE" "$LOG" 2>/dev/null; then
        sleep 1   # let the tail of the log flush
        break
    fi
    sleep "$INTERVAL"
    ELAPSED=$((ELAPSED + INTERVAL))
    if [[ $ELAPSED -ge $TIMEOUT ]]; then
        echo "SELFTEST-HARNESS RESULT: TIMEOUT (${TIMEOUT}s)"
        exit 1
    fi
done

# -----------------------------------------------------------------------------
# 4. Mechanical verdict from serial markers
# -----------------------------------------------------------------------------
PASS_COUNT=$(grep -c '\[selftest\].*PASS' "$LOG" || true)
FAIL_COUNT=$(grep -c '\[selftest\].*FAIL' "$LOG" || true)

echo ""
echo "=== Selftest summary ==="
grep '\[selftest\]' "$LOG" | tail -30 || true
echo ""

if [[ $FAIL_COUNT -eq 0 && $PASS_COUNT -gt 0 ]]; then
    echo "SELFTEST-HARNESS RESULT: PASS ($PASS_COUNT passed, 0 failed)"
    exit 0
elif [[ $FAIL_COUNT -gt 0 ]]; then
    echo "SELFTEST-HARNESS RESULT: FAIL ($PASS_COUNT passed, $FAIL_COUNT failed)"
    exit 1
else
    echo "SELFTEST-HARNESS RESULT: NO-MARKERS (boot failed before any selftest ran?)"
    exit 1
fi
