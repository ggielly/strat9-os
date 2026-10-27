#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
QEMU_BIN="${QEMU:-qemu-system-riscv64}"
TARGET="${TARGET:-riscv64imac-unknown-none-elf}"
KERNEL_ELF="${KERNEL_ELF:-$ROOT_DIR/target/$TARGET/release/kernel}"
QEMU_LOG="${QEMU_LOG:-$ROOT_DIR/build/qemu-riscv.log}"
BIOS="${BIOS:-default}"
SMP="${SMP:-1}"
MEMORY="${MEMORY:-512M}"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
    printf 'QEMU executable not found: %s\n' "$QEMU_BIN" >&2
    exit 127
fi

if [ ! -f "$KERNEL_ELF" ]; then
    printf 'RISC-V kernel not found: %s\n' "$KERNEL_ELF" >&2
    printf 'Build it first with: make -f Makefile.riscv kernel\n' >&2
    exit 1
fi

mkdir -p "$(dirname -- "$QEMU_LOG")"

QEMU_CMD=(
    "$QEMU_BIN"
    -machine virt
    -cpu rv64
    -smp "$SMP"
    -m "$MEMORY"
    -bios "$BIOS"
    -kernel "$KERNEL_ELF"
    -device virtio-rng-device
    -serial stdio
    -display none
    -no-reboot
    -no-shutdown
    -d int,cpu_reset
    -D "$QEMU_LOG"
)

if [ "$#" -gt 0 ]; then
    QEMU_CMD+=("$@")
fi

printf 'QEMU command:'
printf ' %q' "${QEMU_CMD[@]}"
printf '\n'
exec "${QEMU_CMD[@]}"
