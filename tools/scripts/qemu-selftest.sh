#!/usr/bin/env bash
# =============================================================================
# qemu-selftest.sh — L3/L4 automated kernel selftest harness (anti-regression)
#
# Boots the Strat9 kernel (built with the `selftest` feature) under QEMU,
# captures the serial output, and reports PASS/FAIL mechanically.
#
# Exit codes: 0 = all selftests passed, 1 = at least one failure or timeout,
#             2 = usage / environment error.
#
# Usage:
#   tools/scripts/qemu-selftest.sh [--image PATH] [--timeout SECS] [--skip-build]
#
# CI: designed for a GitLab runner with qemu-system-x86_64 installed.
# See docs-site/src/testing-architecture.md (layers L3/L4).
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

ISO="build/strat9-os-selftest.iso"
TIMEOUT=120
SKIP_BUILD=0
QEMU="${QEMU:-qemu-system-x86_64}"
LOG="build/qemu-selftest.log"
MARKER_DONE="[selftest] orchestrator done"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)      ISO="$2"; shift 2 ;;
        --iso)        ISO="$2"; shift 2 ;;
        --timeout)    TIMEOUT="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help)    grep '^#' "$0" | head -20; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

command -v "$QEMU" >/dev/null || { echo "ERROR: $QEMU not found" >&2; exit 2; }

# -----------------------------------------------------------------------------
# 1. Build kernel + ISO with selftests enabled
# -----------------------------------------------------------------------------
if [[ $SKIP_BUILD -eq 0 ]]; then
    echo "==> Building kernel (selftest feature)"
    if ! (cd workspace/kernel && cargo build --target x86_64-unknown-none --features selftest); then
        echo "SELFTEST-HARNESS RESULT: BUILD-FAILED"
        exit 1
    fi
fi

# Fall back to the standard image produced by 'cargo make limine-image'.
if [[ ! -f "$ISO" ]]; then
    ALT="build/strat9-os.iso"
    if [[ -f "$ALT" ]]; then
        echo "==> No dedicated selftest image at $ISO, using $ALT"
        ISO="$ALT"
    else
        echo "ERROR: no bootable image ($ISO or $ALT). Run 'cargo make limine-image' first." >&2
        exit 2
    fi
fi

# -----------------------------------------------------------------------------
# 2. Boot QEMU headless, capture serial, stop on completion marker
# -----------------------------------------------------------------------------
echo "==> Booting $ISO (timeout ${TIMEOUT}s)"
rm -f "$LOG"; : > "$LOG"

"$QEMU" \
    -cdrom "$ISO" \
    -machine q35 \
    -cpu qemu64 \
    -smp 2 \
    -m 512M \
    -serial "file:$LOG" \
    -display none \
    -no-reboot \
    -no-shutdown &
QEMU_PID=$!

cleanup() { kill "$QEMU_PID" 2>/dev/null || true; wait "$QEMU_PID" 2>/dev/null || true; }
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
# 3. Mechanical verdict from serial markers
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
