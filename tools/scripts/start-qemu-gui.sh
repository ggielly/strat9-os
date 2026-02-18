#!/bin/bash
set -e

# Start QEMU in graphical mode by providing a VNC display (:1 -> TCP 5901)
# Usage: start-qemu-gui.sh [--foreground] [extra qemu args]

foreground=false
EXTRA_ARGS=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --foreground|-f)
            foreground=true; shift ;;
        --)
            shift; while [ "$#" -gt 0 ]; do EXTRA_ARGS+=("$1"); shift; done ;;
        *) EXTRA_ARGS+=("$1"); shift ;;
    esac
done

WORKDIR="/workspace"
ISO="$WORKDIR/build/strat9-os.iso"
IMG="$WORKDIR/qemu-stuff/disk.img"
LOG="$WORKDIR/build/qemu-gui.log"
PIDFILE="$WORKDIR/build/qemu-gui.pid"

cd "$WORKDIR"

if [ ! -f "$ISO" ]; then
    echo "ISO not found at $ISO, building image first..."
    bash /workspace/tools/scripts/container-build.sh image
fi
if [ ! -f "$IMG" ]; then
    echo "Disk image not found at $IMG, building image first..."
    bash /workspace/tools/scripts/container-build.sh image
fi

QEMU_CMD=(qemu-system-x86_64
    -cdrom "$ISO"
    -drive "file=$IMG,format=raw,if=none,id=drv0"
    -device "virtio-blk-pci,drive=drv0"
    -machine q35
    -cpu qemu64
    -m 256M
    -vnc :1
    -no-reboot
    -no-shutdown
    -serial mon:stdio
    -D "$LOG"
)

if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
    QEMU_CMD+=("${EXTRA_ARGS[@]}")
fi

echo "QEMU command: ${QEMU_CMD[*]}"

if [ "$foreground" = true ]; then
    exec "${QEMU_CMD[@]}"
else
    nohup bash -lc "\"${QEMU_CMD[@]}\"" >/dev/null 2>&1 &
    echo $! > "$PIDFILE"
    echo "QEMU (GUI/VNC) started (detached) with PID $(cat $PIDFILE)"
    echo "VNC: connect to container:5901; logs: $LOG"
fi