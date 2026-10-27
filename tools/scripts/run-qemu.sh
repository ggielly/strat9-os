#!/bin/bash

# Script de lancement QEMU pour Strat9-OS
# Lance l'image disque bootable

set -e

disk_image="build/strat9-os.img"
qemu="qemu-system-x86_64"
qemu_accel=tcg
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    qemu_accel=kvm
    echo "QEMU acceleration: KVM"
else
    echo "QEMU acceleration: TCG (/dev/kvm unavailable; expose KVM to the host/container for hardware acceleration)"
fi

if [ ! -f "$disk_image" ]; then
    echo "Image disque introuvable: $disk_image"
    exit 1
fi

echo "============================================"
echo "  Lancement de Strat9-OS dans QEMU"
echo "============================================"
echo ""
echo "  Image: $disk_image"
echo "  Sortie serie: build/serial.txt"
echo ""
echo "  Appuyez sur Ctrl+C pour quitter QEMU"
echo "  Souris: mode GTK sans grab-on-hover"
echo ""
echo "============================================"
echo ""

"$qemu" \
    -accel "$qemu_accel" \
    -drive format=raw,file="$disk_image" \
    -machine q35 \
    -cpu qemu64 \
    -m 256M \
    -display gtk,grab-on-hover=off,zoom-to-fit=on \
    -serial file:build/serial.txt \
    -debugcon file:build/qemu-debugcon.log \
    -global isa-debugcon.iobase=0xe9 \
    -no-reboot \
    -no-shutdown \
    -d int,cpu_reset \
    -D build/qemu-debug.log

echo ""
echo "QEMU terminé."
echo ""
echo "Logs:"
if [ -f "build/serial.txt" ]; then
    echo "  - Serial output: build/serial.txt"
    echo ""
    echo "=== SERIAL OUTPUT ==="
    cat "build/serial.txt"
fi
if [ -f "build/qemu-debug.log" ]; then
    echo "  - Debug log: build/qemu-debug.log"
fi
