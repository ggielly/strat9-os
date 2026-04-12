#!/bin/bash
set -e

# Run QEMU in -nographic mode inside the container
# Usage: run-qemu-nographic.sh [--foreground]

foreground=false
EXTRA_ARGS=()
# Parse args: --foreground / -f and pass through other args to QEMU
while [ "$#" -gt 0 ]; do
    case "$1" in
        --foreground|-f)
            foreground=true
            shift
            ;;
        --)
            shift
            while [ "$#" -gt 0 ]; do EXTRA_ARGS+=("$1"); shift; done
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done


# Paths
WORKDIR="/workspace"
ISO="$WORKDIR/build/strat9-os.iso"
IMG="$WORKDIR/qemu-stuff/disk.img"
LOG="$WORKDIR/build/qemu.log"
PIDFILE="$WORKDIR/build/qemu.pid"

# Ensure working dir
cd "$WORKDIR"

# Check iso / image
if [ ! -f "$ISO" ]; then
    echo "ISO not found at $ISO, building image first..."
    bash /workspace/tools/scripts/container-build.sh image
fi
if [ ! -f "$IMG" ]; then
    echo "Disk image not found at $IMG, building image first..."
    bash /workspace/tools/scripts/container-build.sh image
fi

# Ensure build directory exists
mkdir -p build

QEMU_CMD=(qemu-system-x86_64
    -cdrom "$ISO"
    -drive "file=$IMG,format=raw,if=none,id=drv0"
    -device "virtio-blk-pci,drive=drv0"
    -machine q35
    -cpu qemu64
    -m 256M
    -nographic
    -no-reboot
    -no-shutdown
    -serial mon:stdio
    -D "$LOG"
)

# Append any extra args
if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
    QEMU_CMD+=("${EXTRA_ARGS[@]}")
fi

echo "QEMU command: ${QEMU_CMD[*]}"

if [ "$foreground" = true ]; then
    exec "${QEMU_CMD[@]}"
else
    # Start in background and record PID
    nohup bash -lc "\"${QEMU_CMD[@]}\"" >/dev/null 2>&1 &
    echo $! > "$PIDFILE"
    echo "QEMU started (detached) with PID $(cat $PIDFILE)"
    echo "Logs: $LOG"
fi
