#!/bin/bash

# Test de boot rapide avec timeout
qemu="qemu-system-x86_64"
disk_image="build/strat9-os.img"

echo "Testing Strat9-OS boot (10 second timeout)..."
echo ""

# Run QEMU in background
"$qemu" \
    -drive "format=raw,file=$disk_image" \
    -machine q35 \
    -cpu qemu64 \
    -m 256M \
    -serial stdio \
    -display none \
    -no-reboot \
    -no-shutdown \
    -d int,cpu_reset \
    -D qemu-test.log &
qemu_pid=$!

# Wait 10 seconds
sleep 10

# Kill QEMU
kill $qemu_pid 2>/dev/null || true
wait $qemu_pid 2>/dev/null || true

echo "=== OUTPUT ==="
# Since output is to stdio, but in background, hard to capture. Maybe redirect.
# For simplicity, just note that output is in log.

if [ -f "qemu-test.log" ]; then
    echo "=== QEMU LOG (last 30 lines) ==="
    tail -30 "qemu-test.log"
fi