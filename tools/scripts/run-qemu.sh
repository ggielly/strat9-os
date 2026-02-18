#!/bin/bash

# Script de lancement QEMU pour Strat9-OS
# Lance l'image disque bootable

set -e

disk_image="build/strat9-os.img"
qemu="qemu-system-x86_64"

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
echo ""
echo "============================================"
echo ""

"$qemu" \
    -drive format=raw,file="$disk_image" \
    -machine q35 \
    -cpu qemu64 \
    -m 256M \
    -serial file:build/serial.txt \
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