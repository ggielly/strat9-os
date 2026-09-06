#!/bin/bash

# =====================================================================
# Assemble strat9-os bootloader (NASM) — LEGACY boot path
#
# The active boot path is Limine (see tools/scripts/create-limine-image.sh
# and limine.conf). This script assembles the legacy custom BIOS
# bootloader (workspace/bootloader/asm/x86_64/stage1.asm, which %includes
# stage2.asm) for reference/testing.
# =====================================================================

set -e

echo ""
echo "=== Assemblage du bootloader (legacy) ==="
echo ""

# Créer le dossier build
mkdir -p "build"

# Assembler stage1.asm (qui inclut stage2.asm)
asm_dir="workspace/bootloader/asm/x86_64"
output="build/boot.bin"

echo "  Assemblage de $asm_dir/stage1.asm..."

nasm -f bin -I"$asm_dir/" -o "$output" "$asm_dir/stage1.asm"

if [ $? -ne 0 ]; then
    echo "NASM failed to assemble bootloader"
    exit 1
fi

size=$(stat -c%s "$output")
sectors=$(( (size + 511) / 512 ))

echo "  [OK] Bootloader assemblé : boot.bin"
echo "       Taille : $size bytes ($sectors secteurs)"
echo ""

exit 0
