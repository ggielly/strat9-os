#!/usr/bin/env bash
# L3/L4 harness. UEFI is the default for both ISO and raw disk containers.
# PASS requires the complete serial protocol and a controlled QEMU exit 0.
# Usage: qemu-selftest.sh [--iso PATH | --image PATH] [--firmware uefi|bios]
#   [--skip-build] [--timeout SECS] [--smp N] [--mem MB] [--log PATH]
#   [--ovmf-code PATH --ovmf-vars PATH]
# Exit codes: 0 = complete success, 1 = failed/incomplete run, 2 = environment.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 2
DEFAULT_ISO="build/strat9-os-selftest-uefi.iso"
BOOT_IMAGE=""
MEDIA=iso
FIRMWARE=uefi
TIMEOUT=180
SKIP_BUILD=0
SMP=2
MEM_MB=1024
QEMU="${QEMU:-qemu-system-x86_64}"
LOG="build/qemu-selftest.log"
OVMF_CODE="${OVMF_CODE:-}"
OVMF_VARS_SRC="${OVMF_VARS:-}"
# BootPrefixWriter may prepend a timestamp. This marker has no colored token;
# the final verdict additionally normalizes serial.rs SGR colors on PASS/FAIL.
MARKER_DONE='^(\[ *[0-9]+\.[0-9]{6}\] )?\[selftest\] orchestrator done'

usage_error() { echo "ERROR: $*" >&2; exit 2; }
while (( $# )); do
    case "$1" in
        --skip-build) SKIP_BUILD=1; shift; continue ;;
        -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
        --iso|--image|--firmware|--timeout|--smp|--mem|--log|--ovmf-code|--ovmf-vars)
            (( $# >= 2 )) && [[ -n "$2" ]] || usage_error "$1 requires a value" ;;
        *) usage_error "unknown option: $1" ;;
    esac
    case "$1" in
        --iso|--image)
            [[ -z "$BOOT_IMAGE" ]] || usage_error "choose only one --iso or --image"
            BOOT_IMAGE="$2"
            if [[ "$1" == --iso ]]; then MEDIA=iso; else MEDIA=disk; fi ;;
        --firmware) FIRMWARE="$2" ;;
        --timeout) TIMEOUT="$2" ;;
        --smp) SMP="$2" ;;
        --mem) MEM_MB="$2" ;;
        --log) LOG="$2" ;;
        --ovmf-code) OVMF_CODE="$2" ;;
        --ovmf-vars) OVMF_VARS_SRC="$2" ;;
    esac
    shift 2
done
case "$FIRMWARE" in uefi|bios) ;; *) usage_error "firmware must be uefi or bios" ;; esac
for value in "$TIMEOUT" "$SMP" "$MEM_MB"; do
    [[ "$value" =~ ^[1-9][0-9]{0,6}$ ]] || usage_error "timeout/smp/mem must be positive integers"
done
for tool in "$QEMU" python3 grep mktemp mkdir cp rm sleep; do
    command -v "$tool" >/dev/null 2>&1 || usage_error "required tool '$tool' not found"
done

# An explicit artifact is never replaced by a different, implicitly built one.
if [[ -n "$BOOT_IMAGE" ]]; then
    [[ -s "$BOOT_IMAGE" ]] || usage_error "image missing or empty: $BOOT_IMAGE"
else
    [[ "$FIRMWARE" == uefi ]] || usage_error "BIOS mode requires an explicit legacy artifact"
    BOOT_IMAGE="$DEFAULT_ISO"
    if [[ ! -s "$BOOT_IMAGE" && "$SKIP_BUILD" == 0 ]]; then
        command -v cargo >/dev/null 2>&1 || usage_error "cargo missing; supply an image with --skip-build"
        if ! cargo make selftest-iso-uefi; then
            echo "SELFTEST-HARNESS RESULT: BUILD-FAILED"; exit 1
        fi
    fi
    [[ -s "$BOOT_IMAGE" ]] || usage_error "missing $DEFAULT_ISO; build selftest-iso-uefi first"
fi

# Select CODE and VARS as a pair, not independent filesystem-search results.
if [[ "$FIRMWARE" == uefi ]]; then
    if [[ -z "$OVMF_CODE" && -z "$OVMF_VARS_SRC" ]]; then
        for directory in /usr/share/OVMF /usr/share/edk2/x64 /usr/share/edk2-ovmf/x64 /usr/share/edk2/ovmf; do
            for suffix in _4M .4m ""; do
                code="$directory/OVMF_CODE$suffix.fd"
                vars="$directory/OVMF_VARS$suffix.fd"
                if [[ -s "$code" && -s "$vars" ]]; then
                    OVMF_CODE="$code"; OVMF_VARS_SRC="$vars"; break 2
                fi
            done
        done
    fi
    [[ -s "$OVMF_CODE" && -s "$OVMF_VARS_SRC" ]] ||
        usage_error "provide a readable OVMF CODE/VARS pair (--ovmf-code and --ovmf-vars)"
fi

mkdir -p build "$(dirname "$LOG")" || exit 2
BUILD_DIR="$(cd build && pwd -P)" || exit 2
RUN_DIR="$(mktemp -d "$BUILD_DIR/.qemu-selftest.XXXXXXXX")" || exit 2
SERIAL_LOG="$RUN_DIR/serial.log"
QEMU_LOG="$RUN_DIR/qemu.log"
QEMU_PID=""
MONITOR_FD=""
LOGS_SAVED=0
save_logs() {
    cp -- "$SERIAL_LOG" "$LOG" && cp -- "$QEMU_LOG" "$LOG.qemu" || return 1
    LOGS_SAVED=1
}
cleanup() {
    local result=$? resolved
    if [[ -n "$QEMU_PID" ]]; then
        kill "$QEMU_PID" 2>/dev/null || true
        for _ in {1..20}; do
            kill -0 "$QEMU_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    if [[ -n "$MONITOR_FD" ]]; then exec {MONITOR_FD}>&-; fi
    if [[ "$LOGS_SAVED" == 0 ]]; then save_logs || result=1; fi
    resolved="$(cd "$RUN_DIR" && pwd -P)"
    if [[ "${resolved%/*}" == "$BUILD_DIR" && "${resolved##*/}" == .qemu-selftest.* ]]; then
        rm -rf -- "$resolved" || result=1
    else
        echo "ERROR: refusing cleanup outside the QEMU work directory" >&2; result=1
    fi
    trap - EXIT
    exit "$result"
}
: > "$SERIAL_LOG"
: > "$QEMU_LOG"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# A broken monitor pipe is a failed run, not a signal that bypasses cleanup.
trap '' PIPE

QEMU_ARGS=(-machine q35 -cpu qemu64 -smp "$SMP" -m "${MEM_MB}M"
    -serial "file:$SERIAL_LOG" -display none -no-reboot -no-shutdown -monitor stdio)
if [[ "$FIRMWARE" == uefi ]]; then
    cp -- "$OVMF_VARS_SRC" "$RUN_DIR/OVMF_VARS.fd" || exit 2
    QEMU_ARGS+=(
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE//,/,,}"
        -drive "if=pflash,format=raw,file=${RUN_DIR//,/,,}/OVMF_VARS.fd")
fi
if [[ "$MEDIA" == iso ]]; then
    QEMU_ARGS+=(-cdrom "$BOOT_IMAGE")
else
    # Snapshot mode keeps guest writes away from the validated disk artifact.
    QEMU_ARGS+=(-drive "file=${BOOT_IMAGE//,/,,},format=raw,snapshot=on")
fi
echo "==> Booting $BOOT_IMAGE (firmware=$FIRMWARE, media=$MEDIA, timeout=${TIMEOUT}s)"
# Keep a private pipe to the HMP monitor. The kernel need not write a special
# exit I/O port: quit is requested only after the completion marker is seen.
exec {MONITOR_FD}> >(exec "$QEMU" "${QEMU_ARGS[@]}" > "$QEMU_LOG" 2>&1)
QEMU_PID=$!
deadline=$((SECONDS + TIMEOUT))
controlled=0
while kill -0 "$QEMU_PID" 2>/dev/null; do
    if grep -qE "$MARKER_DONE"$'\r?$' "$SERIAL_LOG"; then
        if printf 'quit\n' >&"$MONITOR_FD"; then controlled=1; fi
        break
    fi
    if (( SECONDS >= deadline )); then
        echo "SELFTEST-HARNESS RESULT: TIMEOUT (${TIMEOUT}s)"; exit 1
    fi
    sleep 0.2
done
if [[ "$controlled" == 1 ]]; then
    deadline=$((SECONDS + 5))
    while kill -0 "$QEMU_PID" 2>/dev/null; do
        if (( SECONDS >= deadline )); then
            echo "SELFTEST-HARNESS RESULT: STOP-TIMEOUT"; exit 1
        fi
        sleep 0.1
    done
fi
wait "$QEMU_PID"
qemu_status=$?
QEMU_PID=""
save_logs || { echo "SELFTEST-HARNESS RESULT: LOG-ERROR"; exit 1; }
args=("$SERIAL_LOG" --qemu-status "$qemu_status")
if [[ "$controlled" == 1 ]]; then args+=(--controlled-stop); fi
python3 "$SCRIPT_DIR/selftest-log.py" "${args[@]}"
result=$?
echo "==> Serial log: $LOG; QEMU diagnostics: $LOG.qemu"
exit "$result"
